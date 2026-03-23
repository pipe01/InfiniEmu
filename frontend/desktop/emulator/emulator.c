#include "bluetooth.h"
#include "fault.h"
#include "gdb.h"
#include "ie_time.h"
#include "pinetime.h"
#include "segger_rtt.h"
#include "scheduler.h"

#include <stdio.h>

unsigned long inst_counter = 0;
bool stop_loop = false;

bool found_rtt = false;

static char rtt_buffer[1024];
static int rtt_read;

extern void branch_callback(cpu_t *cpu, unsigned int old_pc, unsigned int new_pc, void *userdata);

typedef struct
{
	pinetime_t *pt;
	rtt_t *rtt;
	bluetooth_t *bt;
} step_deps_t;

static inline void loop_step(step_deps_t *d)
{
	bluetooth_run(d->bt);

	pinetime_step(d->pt);
	inst_counter++;

	if (d->rtt && (found_rtt || inst_counter < 1000000))
	{
		if (inst_counter % 1000 == 0)
		{
			if (!found_rtt)
				found_rtt = rtt_find_control(d->rtt);

			rtt_read = rtt_flush_buffers(d->rtt, rtt_buffer, sizeof(rtt_buffer));
			if (rtt_read > 0)
			{
				fwrite(rtt_buffer, 1, rtt_read, stdout);
				fflush(stdout);
			}
		}
	}
}

static void loop(step_deps_t d)
{
	stop_loop = false;

	while (!stop_loop)
	{
		loop_step(&d);
	}
}

int run_iterations(step_deps_t d, unsigned long iterations, unsigned long iterations_per_us)
{
	unsigned long i;

	jmp_buf fault_jmp;

	int fault = setjmp(fault_jmp);

	if (fault)
	{
		fault_clear_jmp();

		return fault;
	}
	else
	{
		fault_set_jmp(&fault_jmp);

		for (i = 0; i < iterations; i++)
		{
			loop_step(&d);
		}
	}

	fault_clear_jmp();

	return 0;
}

scheduler_t *create_sched(step_deps_t d, size_t freq)
{
	step_deps_t *pd = malloc(sizeof(step_deps_t));
	*pd = d;

	return scheduler_new((scheduler_cb_t)loop_step, pd, freq, d.rtt);
}

int run(int type, scheduler_t *arg, step_deps_t d)
{
	jmp_buf fault_jmp;

	int fault = setjmp(fault_jmp);

	if (fault)
	{
		fault_clear_jmp();

		return fault;
	}
	else
	{
		fault_set_jmp(&fault_jmp);

		switch (type)
		{
		case 0:
			loop(d);
			break;

		case 1:
			scheduler_run(arg);
			break;

		case 2:
			gdb_t *gdb = gdb_new(d.pt, true, (step_emulation_t)loop_step, &d);
			gdb_start(gdb);
			break;
		}
	}

	fault_clear_jmp();

	return 0;
}

void set_cpu_branch_cb(cpu_t *cpu, void *userdata)
{
	if (userdata == NULL)
		cpu_set_branch_cb(cpu, NULL, NULL);
	else
		cpu_set_branch_cb(cpu, branch_callback, userdata);
}

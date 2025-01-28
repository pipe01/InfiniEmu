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

static inline void loop_step(pinetime_t *pt, rtt_t *rtt)
{
	pinetime_step(pt);
	inst_counter++;

	if (rtt && (found_rtt || inst_counter < 1000000))
	{
		if (inst_counter % 1000 == 0)
		{
			if (!found_rtt)
				found_rtt = rtt_find_control(rtt);

			rtt_read = rtt_flush_buffers(rtt, rtt_buffer, sizeof(rtt_buffer));
			if (rtt_read > 0)
			{
				fwrite(rtt_buffer, 1, rtt_read, stdout);
				fflush(stdout);
			}
		}
	}
}

static void loop(pinetime_t *pt, rtt_t *rtt)
{
	stop_loop = false;

	while (!stop_loop)
	{
		loop_step(pt, rtt);
	}
}

int run_iterations(pinetime_t *pt, rtt_t *rtt, unsigned long iterations, unsigned long iterations_per_us)
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
			loop_step(pt, rtt);
		}
	}

	fault_clear_jmp();

	return 0;
}

scheduler_t *create_sched(pinetime_t *pt, size_t freq)
{
	return scheduler_new((scheduler_cb_t)pinetime_step, pt, freq);
}

int run(int type, void *arg, rtt_t *rtt)
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
			loop((pinetime_t *)arg, rtt);
			break;

		case 1:
			scheduler_run((scheduler_t *)arg);
			break;

		case 2:
			gdb_start((gdb_t *)arg);
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

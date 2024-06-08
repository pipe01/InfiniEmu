#include "fault.h"
#include "gdb.h"
#include "pinetime.h"
#include "scheduler.h"

unsigned long inst_counter = 0;
bool stop_loop = false;

extern void branch_callback(cpu_t *cpu, unsigned int old_pc, unsigned int new_pc, void *userdata);

static void loop(pinetime_t *pt)
{
	stop_loop = false;

	while (!stop_loop)
	{
		pinetime_step(pt);
		inst_counter++;
	}
}

scheduler_t *create_sched(pinetime_t *pt, size_t freq)
{
	return scheduler_new((scheduler_cb_t)pinetime_step, pt, freq);
}

int run(int type, void *arg)
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
			loop((pinetime_t *)arg);
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
	cpu_set_branch_cb(cpu, branch_callback, userdata);
}

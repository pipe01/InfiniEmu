void SVC_Handler()
{

}

int main()
{
    // vTaskStartScheduler();

    __asm volatile("svc 0");

    for (;;)
    {
    }
}

void vApplicationMallocFailedHook()
{
}

void vApplicationStackOverflowHook(void *xTask, char *pcTaskName)
{
}

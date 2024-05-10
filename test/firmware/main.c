#include <FreeRTOS.h>
#include <task.h>

#include <SEGGER_RTT.h>

void vTaskCode(void *)
{
  for (;;)
  {
    __asm volatile("nop");
    SEGGER_RTT_WriteString(0, "Tick\n");
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

int main()
{
  SEGGER_RTT_ConfigUpBuffer(0, NULL, NULL, 0, SEGGER_RTT_MODE_BLOCK_IF_FIFO_FULL);

  SEGGER_RTT_WriteString(0, "SEGGER Real-Time-Terminal Sample\n");

  TaskHandle_t xHandle = NULL;
  xTaskCreate(vTaskCode, "NAME", 300, NULL, 1, &xHandle);

  vTaskStartScheduler();

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

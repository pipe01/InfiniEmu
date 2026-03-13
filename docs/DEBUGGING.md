# Debugging code running inside InfiniEmu

InfiniEmu implements the [GDB Remote Serial Protocol](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html), meaning that you can debug code running inside the emulator using tools like `gdb` or IDEs like VS Code.

To start the InfiniEmu desktop frontend in debug mode simply add the `-gdb` option when running it, e.g. `infiniemu-gui -gdb /project/myfirmware.out`.

> [!IMPORTANT]
> If running InfiniTime, make sure not to use the `mcuboot` version. The firmware file's name should be something like `pinetime-app-1.16.0.out`.

## Building InfiniTime for debugging

There's a couple configuration changes you should make to the InfiniTime build process in order to greatly improve your experience when debugging it.

### Debug mode

First and foremost is to build it using CMake's `Debug` build type, which you can enable by adding the `-DCMAKE_BUILD_TYPE=Debug` flag when configuring it with `cmake`. For example:

```shell
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

However, this will greatly increase the output's size, potentially making it bigger than the nRF52832's flash and causing the build to fail. If this occurs, you can make the linker think that the available flash space is larger (InfiniEmu supports up to 8MB) by tweaking the `gcc_nrf52.ld` file at the root of the project:

```diff
 MEMORY
 {
   /* MCUBOOT (r) : ORIGIN = 0x0, LENGTH = MCUBOOT_SIZE */
-  FLASH (rx) : ORIGIN = APP_OFFSET, LENGTH = APP_SIZE
+  FLASH (rx) : ORIGIN = APP_OFFSET, LENGTH = 0x800000
   /* SCRATCH (r) : ORIGIN = SCRATCH_OFFSET, LENGTH = SCRATCH_SIZE */
   SPARE_SPACE (r) : ORIGIN = SCRATCH_OFFSET + SCRATCH_SIZE, LENGTH = 12K
   RAM (rwx) :  ORIGIN = 0x20000000, LENGTH = 64K
 }
```

You may also increase the RAM capacity in a similar manner if necessary by changing the `RAM`'s `LENGTH` to e.g. `128K`.

### Logging

Although not strictly related to debugging as described in this document, it can be very useful to see the messages that the InfiniTime firmware logs when running. To enable this you must uncomment a couple lines in the `src/CMakeLists.txt` file:

```diff
   # NRF SDK Logging
   add_definitions(-DNRF_LOG_ENABLED=1)
-  # add_definitions(-DNRF_LOG_BACKEND_RTT_ENABLED=1)
-  # add_definitions(-DNRF_LOG_BACKEND_SERIAL_USES_RTT=1)
+  add_definitions(-DNRF_LOG_BACKEND_RTT_ENABLED=1)
+  add_definitions(-DNRF_LOG_BACKEND_SERIAL_USES_RTT=1)
```

This will send all log messages to the Segger RTT backend, which InfiniEmu will read and output to its stdout.

## Using Visual Studio Code

You will need the [Native Debug](https://marketplace.visualstudio.com/items?itemName=webfreak.debug) extension, which provides support for connecting to a remote GDB server. Once installed, add the following block to your `launch.json`:

```json
{
    "type": "gdb",
    "request": "attach",
    "name": "Attach to InfiniEmu",
    "executable": "/project/myfirmware.out",
    "target": ":3333",
    "remote": true,
    "cwd": "${workspaceRoot}"
}
```

Make sure to adjust the `executable` so it points to the same firmware file that InfiniEmu is running.

You should now be able to hit F5 (make sure you select the "Attach to InfiniEmu" configuration on the "Run and Debug" sidebar) and connect to the running InfiniEmu instance.

If you want to stop execution right after connecting, you can set either the `"stopAtConnect"` or the `"stopAtEntry"` property to `true`. The former will stop execution at the absolute first instruction that that emulator runs (in our case the reset handler), while the latter will stop at the program's entry point (in our case `main`). For more information, check [the extension's README](https://github.com/WebFreak001/code-debug).

> [!NOTE]
> The firmware won't be automatically built when pressing F5, make sure to build it manually through whichever process you have set up before starting the debugging session.

### Gotchas

* You can't set breakpoints while the program is running. Make sure to pause execution first using either the pause button at the top or the F6 key, set the breakpoint and then resume execution.
* Debugging performance in general seems a bit sluggish in my experience, even with a relatively good PC. Actions like stepping and stopping on breakpoints may take a couple seconds.

## Using GDB

You must use a version of GDB that was compiled with support for the ARMv7-M architecture. To check this, you may run the following command:

```
(gdb) set architecture armv7e-m
The target architecture is set to "armv7e-m".
```

If you see output like the above, you should be good to go. Otherwise, you may want to use a different variant or download one from your distribution's repositories.

> [!NOTE]
> You don't need to input this command every time you start a session, it should be automatically set once you start debugging.

Next you should tell GDB what firmware file will be run using the `file` command, which must be the same file you passed to the InfiniEmu instance you're connecting to:

```
(gdb) file /project/myfirmware.out
```

You may now connect to a running InfiniEmu instance in debug mode:

```
(gdb) target remote :3333
Remote debugging using :3333
```

If all went well you should now see that execution is stopped on the reset handler, e.g.:

```
(gdb) info registers 
r0             0x0                 0
r1             0x0                 0
r2             0x0                 0
r3             0x0                 0
r4             0x0                 0
r5             0x0                 0
r6             0x0                 0
r7             0x0                 0
r8             0x0                 0
r9             0x0                 0
r10            0x0                 0
r11            0x0                 0
r12            0x0                 0
sp             0x20010000          0x20010000
lr             0xffffffff          0xffffffff
pc             0x2f644             0x2f644 <Reset_Handler>
xpsr           0x1000000           16777216
fpscr          0x0                 0
msp            0x20010000          0x20010000
psp            0x0                 0x0 <__isr_vector>
primask        0x0                 0
control        0x0                 0
basepri        0x0                 0
faultmask      0x0                 0
```

You may now use GDB as usual. A tutorial on GDB is out of scope for this document, but here's how to break on the `main` function for completeness' sake:

```
(gdb) br main
Breakpoint 1 at 0x11844
(gdb) c
Continuing.

Breakpoint 1, 0x00011844 in main ()
(gdb) 
```

## Extension commands

InfiniEmu supports a few non-standard commands through the use of the `monitor` GDB command. You can use the "Debug Console" (Ctrl+Shift+Y) on VS Code in order to run these commands.

* `monitor reset`: resets the ARM CPU and all its peripherals (but doesn't clear RAM).
* `monitor step`: makes the ARM CPU run exactly one instruction and pauses execution again. This behaves like `stepi` GDB instruction, which you should prefer using.
* `monitor quit`: closes the connection from the server side.
* `monitor reg sX`: reads scalar register X, with X in [0, 31].
* `monitor pin X`: toggles GPIO pin X on and off, with X in [0, 31].
* `monitor brmemw X`: sets a memory write watchpoint at memory address X (in decimal or hexadecimal format). Execution will break if any write to this memory address is detected. Note that only one watchpoint may be active at the same time.

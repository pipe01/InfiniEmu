declare const tag: unique symbol;

export type Pointer = { readonly [tag]: "Pointer" };
export type Program = { readonly [tag]: "Program" };
export type Pinetime = { readonly [tag]: "Pinetime" };
export type ST7789 = { readonly [tag]: "ST7789" };
export type CST816S = { readonly [tag]: "CST816S" };
export type NRF52832 = { readonly [tag]: "NRF52832" };
export type CPU = { readonly [tag]: "CPU" };
export type Memory = { readonly [tag]: "Memory" };
export type Pins = { readonly [tag]: "Pins" };
export type Commander = { readonly [tag]: "Commander" };
export type RTT = { readonly [tag]: "RTT" };

const module: EmscriptenModuleFactory<EmscriptenModule & {
    ccall(name: string, returnType: string | null, argTypes: string[], args: any[]): any;

    _program_new(size: number): Program;

    _pinetime_new(program: Program, bigRam: boolean): Pinetime;
    _pinetime_get_st7789(pt: Pinetime): ST7789;
    _pinetime_get_cst816s(pt: Pinetime): CST816S;
    _pinetime_get_nrf52832(pt: Pinetime): NRF52832;
    _pinetime_loop(pt: Pinetime, iterations: number): boolean;

    _nrf52832_get_pins(nrf: NRF52832): Pins;
    _nrf52832_get_cpu(nrf: NRF52832): CPU;
    _nrf52832_get_used_sram(nrf: NRF52832): number;

    _cpu_is_sleeping(cpu: CPU): boolean;
    _cpu_mem(cpu: CPU): Memory;

    _st7789_is_sleeping(lcd: ST7789): boolean;
    _st7789_read_screen_rgba(lcd: ST7789, buffer: Pointer, rgbaBuffer: Pointer, width: number, height: number): void;

    _cst816s_do_touch(touch: CST816S, gesture: number, x: number, y: number): void;
    _cst816s_release_touch(touch: CST816S): void;

    _pins_set(pin: Pins, pinNumber: number): void;
    _pins_clear(pin: Pins, pinNumber: number): void;

    _commander_new(pt: Pinetime): Commander;
    _commander_set_output(cmd: Commander, output: Pointer): void;

    _rtt_new(mem: Memory): RTT;
    _rtt_find_control(rtt: RTT): boolean;
    _rtt_flush_buffers(rtt: RTT, buffer: Pointer, bufferSize: number): number;

    UTF8ToString(ptr: Pointer, maxBytes?: number): string;

    _commander_output: Pointer;
}>;

export default module;

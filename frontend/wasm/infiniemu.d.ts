declare const tag: unique symbol;

export type Pointer = { readonly [tag]: "Pointer" };
export type Program = { readonly [tag]: "Program" };
export type Pinetime = { readonly [tag]: "Pinetime" };
export type ST7789 = { readonly [tag]: "ST7789" };
export type CST816S = { readonly [tag]: "CST816S" };
export type NRF52832 = { readonly [tag]: "NRF52832" };
export type SPINorFlash = { readonly [tag]: "SPINorFlash" };
export type CPU = { readonly [tag]: "CPU" };
export type Memory = { readonly [tag]: "Memory" };
export type Pins = { readonly [tag]: "Pins" };
export type Commander = { readonly [tag]: "Commander" };
export type RTT = { readonly [tag]: "RTT" };
export type LFS = { readonly [tag]: "LFS" };
export type LFSDir = { readonly [tag]: "LFSDir" };
export type LFSInfo = { readonly [tag]: "LFSInfo" };
export type LFSFile = { readonly [tag]: "LFSInfo" };

const module: EmscriptenModuleFactory<EmscriptenModule & {
    ccall(name: string, returnType: string | null, argTypes: string[], args: any[]): any;

    _program_new(size: number): Program;
    _program_write_variable(program: Program, cpu: CPU, name: Pointer, lower: number, upper: number): boolean;

    _pinetime_new(program: Program): Pinetime;
    _pinetime_get_st7789(pt: Pinetime): ST7789;
    _pinetime_get_cst816s(pt: Pinetime): CST816S;
    _pinetime_get_nrf52832(pt: Pinetime): NRF52832;
    _pinetime_get_spinorflash(pt: Pinetime): SPINorFlash;
    _pinetime_loop(pt: Pinetime, iterations: number): boolean;
    _pinetime_reset(pt: Pinetime): void;

    _nrf52832_get_pins(nrf: NRF52832): Pins;
    _nrf52832_get_cpu(nrf: NRF52832): CPU;
    _nrf52832_get_used_sram(nrf: NRF52832): number;
    _nrf52832_get_sram_size(nrf: NRF52832): number;

    _cpu_is_sleeping(cpu: CPU): boolean;
    _cpu_mem(cpu: CPU): Memory;

    _st7789_is_sleeping(lcd: ST7789): boolean;
    _st7789_read_screen_rgba(lcd: ST7789, buffer: Pointer, rgbaBuffer: Pointer, width: number, height: number): void;

    _cst816s_do_touch(touch: CST816S, gesture: number, x: number, y: number): void;
    _cst816s_release_touch(touch: CST816S): void;

    _pins_set(pin: Pins, pinNumber: number): void;
    _pins_clear(pin: Pins, pinNumber: number): void;

    _spinorflash_get_buffer(flash: SPINorFlash): Pointer;
    _spinorflash_get_buffer_size(flash: SPINorFlash): number;

    _commander_new(pt: Pinetime): Commander;
    _commander_set_wasm_output(cmd: Commander): void;
    _commander_run_command(cmd: Commander, command: Pointer): void;

    _rtt_new(mem: Memory): RTT;
    _rtt_find_control(rtt: RTT): boolean;
    _rtt_flush_buffers(rtt: RTT, buffer: Pointer, bufferSize: number): number;

    _lfs_init(data: Pointer, dataSize: number): LFS;
    _lfs_free_wasm(lfs: LFS): void;
    _lfs_dir_malloc(): LFSDir;
    _lfs_info_malloc(): LFSInfo;
    _lfs_open_dir(lfs: LFS, path: Pointer): LFSDir;
    _lfs_dir_read(lfs: LFS, dir: LFSDir, info: LFSInfo): number;
    _lfs_info_type(info: LFSInfo): number;
    _lfs_info_size(info: LFSInfo): number;
    _lfs_info_name(info: LFSInfo): Pointer;
    _lfs_open_file(lfs: LFS, path: Pointer, flags: number): LFSFile;
    _lfs_file_close(lfs: LFS, file: LFSFile): number;
    _lfs_file_read(lfs: LFS, file: LFSFile, buffer: Pointer, size: number): number;
    _lfs_file_write(lfs: LFS, file: LFSFile, buffer: Pointer, size: number): number;
    _lfs_mkdir(lfs: LFS, path: Pointer): number;

    UTF8ToString(ptr: Pointer, maxBytes?: number): string;
    stringToNewUTF8(str: string): Pointer;

    _commander_output: Pointer;
}>;

export default module;

export type FileInfo = {
    name: string;
    fullPath: string;
    size: number;
    type: "file" | "dir";
};

export type MessageToWorkerType = { messageId?: number } & (
    { type: "setCanvas", data: OffscreenCanvas } |
    { type: "setBackupTime", data: Date } |
    { type: "start", data: void } |
    { type: "stop", data: void } |
    { type: "doTouch", data: { gesture: number, x: number, y: number } } |
    { type: "clearTouch", data: void } |
    { type: "pressButton", data: void } |
    { type: "releaseButton", data: void } |
    { type: "setProgram", data: ArrayBuffer } |
    { type: "readDir", data: string } |
    { type: "readFile", data: string } |
    { type: "writeFile", data: { path: string, data: ArrayBuffer } } |
    { type: "createDir", data: string } |
    { type: "backupFS", data: void } |
    { type: "restoreFS", data: ArrayBuffer } |
    { type: "loadArchiveFS", data: { path: string, zipData: ArrayBuffer } } |
    { type: "turboMode", data: boolean } |
    { type: "reset", data: void } |
    { type: "runCommand", data: string }
);

export type MessageFromWorkerType = { replyToId?: number } & (
    { type: "ready", data: void } |
    { type: "done", data: void } |
    { type: "error", data: { message: string | undefined, stack: string | undefined, string: string | undefined } } |
    { type: "dirFiles", data: FileInfo[] } |
    { type: "fileData", data: { path: string, data: ArrayBuffer } } |
    { type: "running", data: boolean } |
    { type: "rttFound", data: void } |
    { type: "rttData", data: string } |
    { type: "lcdSleeping", data: boolean } |
    { type: "cpuSleeping", data: boolean } |
    { type: "performance", data: { loopTime: number, ips: number, totalSRAM: number, pins: number } } |
    { type: "backupData", data: ArrayBuffer } |
    { type: "commandOutput", data: string } |
    { type: "aborted", data: any }
);

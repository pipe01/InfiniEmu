import { customRef, onUnmounted, type Ref } from "vue";
import type { MessageFromWorkerType, MessageToWorkerType } from "./common";
import { type FS, fs, type ZipEntry, type ZipFileEntry } from "@zip.js/zip.js";

export function useAverage(interval: number): Ref<number> {
    let sum = 0;
    let count = 0;

    let int: number;

    onUnmounted(() => clearInterval(int));

    return customRef((track, trigger) => {
        let avg = 0;

        int = setInterval(() => {
            avg = sum / count;
            sum = 0;
            count = 0;
            trigger();
        }, interval);

        return {
            get() {
                track();
                return avg;
            },
            set(value) {
                sum += value;
                count++;
            },
        }
    });
}

export function sendMessage<Type extends MessageToWorkerType["type"]>(worker: Worker, type: Type, data: Extract<MessageToWorkerType, { type: Type }>["data"], transfer?: Transferable[]) {
    const messageId = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER);

    if (transfer)
        worker.postMessage({ type, data, messageId }, transfer);
    else
        worker.postMessage({ type, data, messageId });

    return messageId;
}

// I'm sorry
export function sendMessageAndWait<Type extends MessageToWorkerType["type"], ReplyType extends MessageFromWorkerType["type"]>(
    worker: Worker, type: Type,
    data: Extract<MessageToWorkerType, { type: Type }>["data"],
    replyType: ReplyType = "done" as ReplyType,
    transfer?: Transferable[]): Promise<Extract<MessageFromWorkerType, { type: ReplyType }>["data"]> {
    return new Promise<any>((resolve, reject) => {
        let messageId: number;

        const listener = (e: MessageEvent) => {
            const message = e.data as MessageFromWorkerType;

            if (message.replyToId == messageId) {
                worker.removeEventListener("message", listener);

                if (message.type == replyType) {
                    resolve(message.data as any);
                } else if (message.type == "error") {
                    reject(message.data);
                }
            }
        };

        worker.addEventListener("message", listener);
        messageId = sendMessage(worker, type, data as any, transfer);
    });
}

export function downloadURL(url: string, filename: string) {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
}

export function downloadBuffer(data: BlobPart, filename: string) {
    const blob = new Blob([data], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);

    downloadURL(url, filename);

    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function joinLFSPaths(...paths: string[]) {
    return paths.join("/").replace(/^\//, "").replace(/\/+/g, "/");
}

export function isFile(file: ZipEntry): file is ZipFileEntry<void, void> {
    return !(file as any).directory;
}

export async function getZipOrNested(data: Uint8Array, maxDepth = 5): Promise<FS> {
    const zip = new fs.FS();
    await zip.importUint8Array(data);

    if (zip.root.children.length == 1 && isFile(zip.root.children[0]) && zip.root.children[0].name.endsWith(".zip")) {
        if (maxDepth == 0)
            throw new Error("Max depth reached");

        return await getZipOrNested(await zip.root.children[0].getUint8Array(), maxDepth - 1);
    } else {
        return zip;
    }
}

export function resolveArtifactUrl(url: string) {
    const matches = /artifact:\/\/(.+\/.+)\/(\d+)/.exec(url);
    if (matches) {
        return `https://corsproxy.io/?url=https://nightly.link/${matches[1]}/actions/artifacts/${matches[2]}.zip`;
    }

    return url;
}

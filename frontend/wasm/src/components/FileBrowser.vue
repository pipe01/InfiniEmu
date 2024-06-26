<template lang="pug">
div
    button.btn.btn-info(@click="refresh" :disabled="!isInitialized" title="Refresh")
        i.bi-arrow-clockwise
    button.btn.btn-primary.ms-2(@click="createFolder" title="Create folder")
        i.bi-folder-plus
    button.btn.btn-primary.ms-2(@click="writeFile" title="Upload file")
        i.bi-file-earmark-arrow-up
    button.btn.btn-primary.ms-2(@click="writeArchive" title="Upload archive")
        i.bi-file-earmark-zip
    button.btn.btn-secondary.ms-2(@click="createBackup") Backup
    button.btn.btn-secondary.ms-2(@click="restoreBackup") Restore

.mt-2.fs-5 /{{ currentPath }}

.file-item(v-for="file in files" @click="file.type == 'file' ? openFile(file) : navigate(file)")
    i.me-2(:class="[file.type == 'file' ? 'bi-file-earmark' : 'bi-folder2']")
    span {{ file.name }}

    span.float-end.text-muted(v-if="file.type == 'file'") {{ file.size }} bytes
</template>

<script lang="ts" setup>
import { ref } from 'vue';

import type { FileInfo } from '@/common';
import { downloadBuffer, joinLFSPaths, sendMessageAndWait } from '@/utils';
import { fs, type ZipFileEntry, type ZipEntry } from '@zip.js/zip.js';

const props = defineProps<{
    worker: Worker,
    isInitialized: boolean,
}>();

const emit = defineEmits<{
    (e: "loadStart"): void,
    (e: "loadEnd"): void,
}>();

const files = ref<FileInfo[]>([]);

const currentPath = ref("");

async function refresh(emitLoad = true) {
    if (emitLoad)
        emit("loadStart");

    const data = await sendMessageAndWait(props.worker, "readDir", currentPath.value, "dirFiles")

    if (emitLoad)
        emit("loadEnd");

    files.value = data;
}

function navigate(dir: FileInfo) {
    if (dir.name == ".")
        return;
    else if (dir.name == "..") {
        if (currentPath.value == "")
            return;

        const currentPathParts = currentPath.value.split("/");
        currentPathParts.pop();
        currentPath.value = currentPathParts.join("/");
    }
    else {
        currentPath.value = dir.fullPath;
    }

    refresh();
}

async function openFile(file: FileInfo) {
    emit("loadStart");

    const { data } = await sendMessageAndWait(props.worker, "readFile", file.fullPath, "fileData")

    emit("loadEnd");

    downloadBuffer(data, file.name);
}

async function createFolder() {
    const folderName = prompt("Enter folder name");

    if (folderName) {
        const path = joinLFSPaths(currentPath.value, folderName);

        emit("loadStart");

        await sendMessageAndWait(props.worker, "createDir", path);
        refresh(false);

        emit("loadEnd");
    }
}

async function createBackup() {
    emit("loadStart");

    const data = await sendMessageAndWait(props.worker, "backupFS", undefined, "backupData");

    emit("loadEnd");

    downloadBuffer(data, "backup.bin");
}

function pickFile(fn: (data: ArrayBuffer, filename: string) => void) {
    const input = document.createElement('input');
    input.type = 'file';
    input.onchange = () => {
        const reader = new FileReader();
        reader.onload = () => {
            fn(reader.result as ArrayBuffer, input.files![0].name);
        };
        reader.readAsArrayBuffer(input.files![0]);
    }
    input.click();
}

function restoreBackup() {
    pickFile(async (data) => {
        emit("loadStart");

        await sendMessageAndWait(props.worker, "restoreFS", data);
        refresh(false);

        emit("loadEnd");
    });
}

function writeFile() {
    pickFile(async (data, name) => {
        emit("loadStart");

        const path = joinLFSPaths(currentPath.value, name);
        await sendMessageAndWait(props.worker, "writeFile", { path, data }, undefined, [data]);

        refresh(false);

        emit("loadEnd");
    });
}

function isFile(file: ZipEntry): file is ZipFileEntry<void, void> {
    return !(file as any).directory;
}

function writeArchive() {
    pickFile(async (data) => {
        emit("loadStart");

        const zip = new fs.FS();
        await zip.importUint8Array(new Uint8Array(data));

        let importedResources = false;

        const resourcesFile = zip.find("resources.json");
        if (resourcesFile && isFile(resourcesFile))
        {
            const resourcesData = await resourcesFile.getText();
            const manifest = JSON.parse(resourcesData) as { resources: { filename: string, path: string }[] };

            if ("resources" in manifest)
            {
                const createdDirs = new Set<string>();
                
                for (const res of manifest.resources) {
                    const file = zip.find(res.filename);
                    if (file && isFile(file))
                    {
                        const path = joinLFSPaths(currentPath.value, res.path);
                        const fileData = await file.getUint8Array();

                        const parts = res.path.split("/").reduce((acc, part) => [...acc, joinLFSPaths(...acc, part)], [] as string[]);
                        for (const dir of parts.slice(1, -1)) {
                            const path = joinLFSPaths(currentPath.value, dir);
                            
                            if (!createdDirs.has(path)) {
                                await sendMessageAndWait(props.worker, "createDir", path);
                                createdDirs.add(path);
                            }
                        }

                        await sendMessageAndWait(props.worker, "writeFile", { path, data: fileData });
                    }
                }

                importedResources = true;
            }
        }

        if (!importedResources)
        {
            // TODO: Implement
            alert("Only InfiniTime resource archives are supported at the moment.");
        }

        refresh(false);

        emit("loadEnd");
    });
}
</script>

<style lang="scss">
.file-item {
    display: block;
    padding: 0.5rem;
    border-bottom: 1px solid #cccccc70;
    cursor: pointer;

    &:hover {
        background-color: #cccccc20;
    }
}
</style>

<template lang="pug">
div
    button.btn.btn-info(@click="refresh" :disabled="!isInitialized" title="Refresh")
        i.bi-arrow-clockwise
    button.btn.btn-primary.ms-2(@click="createFolder" title="Create folder")
        i.bi-folder-plus
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
        console.log(dir.fullPath);
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

async function restoreBackup() {
    const input = document.createElement('input');
    input.type = 'file';
    input.onchange = () => {
        const reader = new FileReader();
        reader.onload = async () => {
            emit("loadStart");

            await sendMessageAndWait(props.worker, "restoreFS", reader.result as ArrayBuffer, undefined);

            refresh(false);

            emit("loadEnd");
        };
        reader.readAsArrayBuffer(input.files![0]);
    }
    input.click();
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

<template lang="pug">
div
    button.btn.btn-primary(@click="refresh" :disabled="!isInitialized") Refresh
    button.btn.btn-secondary.ms-2(@click="createFolder") Create folder

.mt-2.fs-5 /{{ currentPath }}

.file-item(v-for="file in files" @click="file.type == 'file' ? openFile(file) : navigate(file)")
    i.me-2(:class="[file.type == 'file' ? 'bi-file-earmark' : 'bi-folder2']")
    span {{ file.name }}

    span.float-end.text-muted(v-if="file.type == 'file'") {{ file.size }} bytes
</template>

<script lang="ts" setup>
import { ref } from 'vue';

import type { FileInfo, MessageFromWorkerType } from '@/common';
import { downloadURL, sendMessage } from '@/utils';

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

function refresh() {
    const listener = (event: MessageEvent) => {
        const { type, data } = event.data as MessageFromWorkerType;

        if (type === "dirFiles") {
            files.value = data;
            props.worker.removeEventListener("message", listener);
            emit("loadEnd");
        }
    };

    emit("loadStart");

    props.worker.addEventListener("message", listener);
    sendMessage(props.worker, "readDir", currentPath.value);
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

function openFile(file: FileInfo) {
    const listener = (event: MessageEvent) => {
        const { type, data } = event.data as MessageFromWorkerType;

        if (type == "fileData" && data.path == file.fullPath) {
            props.worker.removeEventListener("message", listener);
            emit("loadEnd");

            const blob = new Blob([data.data], { type: "application/octet-stream" });
            const url = URL.createObjectURL(blob);

            downloadURL(url, file.name);

            setTimeout(() => URL.revokeObjectURL(url), 1000);
        }
    };

    emit("loadStart");

    props.worker.addEventListener("message", listener);
    sendMessage(props.worker, "readFile", file.fullPath);
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

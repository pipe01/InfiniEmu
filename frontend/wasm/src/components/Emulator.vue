<template lang="pug">
template(v-if="!isReady")
    h1 Loading worker...
.row(v-else)
    .col
    .col
        Display(:width="240" :height="240" @got-canvas="onGotCanvas")
        div
            button.btn.btn-success(@click="start") Start
            button.btn.btn-danger.ms-3(@click="stop") Stop
    .col
</template>

<script lang="ts" setup>
import { onUnmounted, ref } from "vue";

import MyWorker from "@/worker?worker";

import Display from "@/components/Display.vue";

const props = defineProps<{
    programFile: ArrayBuffer;
}>();

const isReady = ref(false);

const worker = new MyWorker();
onUnmounted(() => worker.terminate());

worker.onmessage = (event) => {
    const { type, data } = event.data;

    switch (type) {
        case "error":
            console.error("worker error", data);
            break;

        case "ready":
            worker.postMessage({ type: "loadProgram", data: props.programFile });
            isReady.value = true;
            break;
    }
};

function onGotCanvas(canvas: HTMLCanvasElement) {
    const offscreen = canvas.transferControlToOffscreen();

    worker.postMessage({ type: "setCanvas", data: offscreen }, [offscreen]);
}

function start() {
    worker.postMessage({ type: "start" });
}

function stop() {
    worker.postMessage({ type: "stop" });
}
</script>
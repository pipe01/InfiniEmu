<template lang="pug">
template(v-if="!isReady")
    h1 Loading worker...
.row(v-else)
    .col
        .card
            .card-body
                h3.card-title File system

                FileBrowser(:worker="worker" :is-initialized="isStarted" @loadStart="onFileLoadStart" @loadEnd="onFileLoadEnd")
        .card.mt-3(v-if="isStarted")
            .card-body
                h3.card-title Console
                .text-danger(v-if="!foundRTT") Couldn't find Segger RTT block in memory. This probably means that your program doesn't have RTT/logging enabled.

                Console(:lines="consoleLines" canRunCommands style="height: 400px" @runCommand="sendMessage(worker, 'runCommand', $event)")

        .card.mt-3(v-if="isStarted")
            .card-body
                h3.card-title Pins
                table.table.table-bordered.table-striped
                    thead
                        tr
                            th Pin
                            th Name
                            th Mode
                            th Value
                    tbody
                        tr(v-for="(value, index) in pins")
                            td {{ pinetimePins[index].number }}
                            td {{ pinetimePins[index].name }}
                            td {{ pinetimePins[index].dir == "i" ? "Input" : pinetimePins[index].dir == "o" ? "Output" : "Input & Output" }}{{ pinetimePins[index].analog ? " (analog)" : "" }}
                            td
                                input(v-if="!pinetimePins[index].analog" type="checkbox" :disabled="!pinetimePins[index].canChange" :checked="value" @change="setPin(pinetimePins[index].number, $event.target.checked)")
                                template(v-else)
                                    input(type="range" :disabled="!pinetimePins[index].canChange" :value="value" min="0" max="4000" @input="setPin(pinetimePins[index].number, $event.target.value / 1000)")
                                    span {{ (value / 1000).toFixed(2) }} V

    .col(style="flex-grow: 0")
        Display(:width="240" :height="240" :off="isLcdOff" @got-canvas="onGotCanvas"
            @button-down="onButtonDown" @start-swipe="onStartSwipe" @end-swipe="clearTouch"
            @start-touch="onStartTouch" @end-touch="clearTouch")

        .d-flex.flex-column.align-items-stretch.mt-3
            div.text-danger(v-if="isAborted") Emulator aborted
    
            button.btn.btn-success(v-if="!isRunning" @click="start" :disabled="isAborted") Start
            button.btn.btn-danger(v-else @click="stop" :disabled="isAborted") Pause
            button.btn.btn-warning.mt-2(v-if="isStarted" @click="reset" :disabled="isAborted") Reset
            button.btn.btn-primary.mt-2(@click="copyScreen") Copy screen

    .col-3
        template(v-if="isStarted")
            .card
                .card-body
                    h3.card-title Performance
                    div {{ numberFmt.format(performance.cps.value.toFixed(0)) }} Hz ({{speedPercentage.toFixed(0)}}%)
                    div Loop time: {{ performance.loopTime.value.toFixed(0) }} ms
                    div CPU: {{ isCpuSleeping ? "Sleeping" : "Running" }}
                    div RAM size: {{ numberFmt.format(performance.sramSize.value) }} bytes

            .card.mt-3(v-if="isRunning")
                .card-body
                    h3.card-title Controls

                    .d-flex.flex-column.justify-content-center.align-items-center
                        table
                            tr
                                td
                                td
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Up)")
                                        i.bi-caret-up-fill
                            tr
                                td
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Left)")
                                        i.bi-caret-left-fill
                                td
                                    button.btn.btn-primary(@mousedown="onButtonDown(true)" @mouseup="onButtonDown(false)")
                                        i.bi-square-fill
                                td
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Right)")
                                        i.bi-caret-right-fill
                            tr
                                td
                                td
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Down)")
                                        i.bi-caret-down-fill
</template>

<script lang="ts" setup>
import { computed, onUnmounted, ref, watch } from "vue";

import MyWorker from "@/worker?worker";

import Display, { Direction } from "@/components/Display.vue";
import Console, { type Line } from "@/components/Console.vue";
import FileBrowser from "@/components/FileBrowser.vue";
import { sendMessage, sendMessageAndWait, useAverage } from "@/utils";
import { type MessageFromWorkerType } from "@/common";
import { pinetimePins } from "@/pinetime";

const props = defineProps<{
    programFile: ArrayBuffer,
    autoStart: boolean,
    initResources?: Uint8Array[],
    initTime?: Date,
}>();

const GESTURE_NONE = 0x00;
const GESTURE_SLIDEDOWN = 0x01;
const GESTURE_SLIDEUP = 0x02;
const GESTURE_SLIDELEFT = 0x03;
const GESTURE_SLIDERIGHT = 0x04;
const GESTURE_SINGLETAP = 0x05;
const GESTURE_DOUBLETAP = 0x0B;
const GESTURE_LONGPRESS = 0x0C;

const HIGH_VOLTAGE = 3;

const numberFmt = new Intl.NumberFormat();

const isReady = ref(false);
const isStarted = ref(false);
const isRunning = ref(false);
const isAborted = ref(false);

const wasRunningBeforeLoad = ref(false);

const isLcdOff = ref(true);
const isCpuSleeping = ref(false);

const foundRTT = ref(false);

const pins = ref<(number | boolean)[]>([]);

const consoleLines = ref<Line[]>([]);

const canvas = ref<HTMLCanvasElement | null>(null);

function addConsoleLine(text: string, type: Line["type"]) {
    consoleLines.value.push({ text, type });

    if (consoleLines.value.length > 1000) {
        consoleLines.value.splice(0, consoleLines.value.length - 1000);
    }
}

const performance = {
    cps: useAverage(1000),
    loopTime: useAverage(1000),
    sramSize: ref(0),
}

const speedPercentage = computed(() => performance.cps.value / 64000000 * 100);

const worker = new MyWorker();
onUnmounted(() => worker.terminate());

worker.onerror = (event) => {
    console.error("worker error", event);
};

worker.onmessage = async (event) => {
    const { type, data } = event.data as MessageFromWorkerType;

    switch (type) {
        case "error":
            console.error("worker error", data);
            break;

        case "ready":
            await sendMessageAndWait(worker, "setProgram", props.programFile);
            isReady.value = true;

            if (props.initResources) {
                for (const res of props.initResources) {
                    await sendMessageAndWait(worker, "loadArchiveFS", { path: "", zipData: res });
                }
            }
            if (props.initTime) {
                await sendMessageAndWait(worker, "setBackupTime", props.initTime);
            }

            if (props.autoStart)
                start();

            break;

        case "running":
            isRunning.value = data;
            break;

        case "lcdSleeping":
            isLcdOff.value = data;
            break;

        case "cpuSleeping":
            isCpuSleeping.value = data;
            break;

        case "performance":
            performance.cps.value = data.cps;
            performance.loopTime.value = data.loopTime;
            performance.sramSize.value = data.totalSRAM;
            break;

        case "pins":
            pins.value = data;
            break;

        case "rttFound":
            foundRTT.value = true;
            break;

        case "rttData":
            data.split("\n").forEach(o => addConsoleLine(o, "serial"));
            break;

        case "commandOutput":
            addConsoleLine(data, "command");
            break;

        case "aborted":
            isAborted.value = true;
            isRunning.value = false;
            break;
    }
};

function onGotCanvas(canvasEl: HTMLCanvasElement) {
    const offscreen = canvasEl.transferControlToOffscreen();

    sendMessage(worker, "setCanvas", offscreen, [offscreen]);

    canvas.value = canvasEl;
}

function start() {
    sendMessage(worker, "start", undefined);
    isStarted.value = true;
}

function stop() {
    sendMessage(worker, "stop", undefined);
}

function onFileLoadStart() {
    wasRunningBeforeLoad.value = isRunning.value;
    stop();
}

function onFileLoadEnd() {
    if (wasRunningBeforeLoad.value)
        start();
}

function onButtonDown(isDown: boolean) {
    sendMessage(worker, "setPinVoltage", { pin: 13, value: isDown ? HIGH_VOLTAGE : 0 });
}

const swipeCenter = (direction: Direction) => {
    onStartSwipe(direction, 240 / 2, 240 / 2)
    setTimeout(clearTouch, 100);
};

function onStartSwipe(direction: Direction, x: number, y: number) {
    let gesture: number;
    switch (direction) {
        case Direction.Left:
            gesture = GESTURE_SLIDELEFT;
            break;
        case Direction.Right:
            gesture = GESTURE_SLIDERIGHT;
            break;
        case Direction.Up:
            gesture = GESTURE_SLIDEUP;
            break;
        case Direction.Down:
            gesture = GESTURE_SLIDEDOWN;
            break;
        default:
            return;
    }

    sendMessage(worker, "doTouch", { gesture, x, y });
}

function clearTouch() {
    sendMessage(worker, "clearTouch", undefined);
}

function onStartTouch(x: number, y: number, isLongPress = false) {
    sendMessage(worker, "doTouch", { gesture: isLongPress ? GESTURE_LONGPRESS : GESTURE_SINGLETAP, x, y });
}

function reset() {
    sendMessage(worker, "reset", undefined);
}

function setPin(index: number, value: boolean | number) {
    sendMessage(worker, "setPinVoltage", { pin: index, value: typeof value === "boolean" ? (value ? HIGH_VOLTAGE : 0) : value });
}

function copyScreen() {
    if (canvas.value) {
        canvas.value.toBlob((blob) => {
            if (blob) {
                const item = new ClipboardItem({ [blob.type]: blob });
                navigator.clipboard.write([item]);
            }
        });
    }
}
</script>

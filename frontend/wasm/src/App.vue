<template lang="pug">
.container.mt-3

    template(v-if="isLoading")
        h1 Loading...
    template(v-else-if="!pickedFile")
        h1 InfiniEmu

        h4 Select a program file
        .mb-3
            input.form-control(type="file" @change="loadFile($event.target.files[0])")

        h4 or 
            a.btn.btn-primary(href="/?firmware=https://share.pipe01.net/-XpJvumKzSS/pinetime-app-1.14.0.bin&resources=https://share.pipe01.net/-LJ2sU2m3Yc/infinitime-resources-1.14.0.zip")
                | Load sample file

        .form-check.form-switch
            input.form-check-input(type="checkbox" v-model="autoStart" id="autoStart")
            label.form-check-label(for="autoStart") Start emulation after loading file

        hr

        p
            | InfiniEmu is an emulator that emulates a full PineTime smartwatch, which includes:
            ul
                li NRF52832 along with its ARM Cortex M4 CPU and peripherals
                li BMA425 I2C accelerometer
                li CST816S I2C touch screen controller
                li HRS3300 I2C heart rate sensor
                li ST7789 SPI LCD display controller
                li A generic SPI flash based on the XT25F32B-S

        p This website hosts a WebAssembly version of the emulator, which is compiled from the original C code.

        a(href="https://github.com/pipe01/InfiniEmu") View on GitHub

    template(v-else)
        Emulator(:programFile="pickedFile" :autoStart="autoStart" :initResources="initResources")
</template>

<script lang="ts" setup>
import { ref } from 'vue';

import Emulator from "@/components/Emulator.vue";

const pickedFile = ref<ArrayBuffer | null>(null);
const isLoading = ref(false);

const autoStart = ref(true);
const initResources = ref<Uint8Array[]>([]);

async function parseOptions(params: URLSearchParams) {
    if (params.has("firmware")) {
        await loadFileFromURL(params.get("firmware")!);
    }
    if (params.has("resources")) {
        for (const url of params.getAll("resources")) {
            const response = await fetch(url);
            const resource = new Uint8Array(await response.arrayBuffer());

            initResources.value.push(resource);
        }
    }
}
parseOptions(new URLSearchParams(location.search));

async function loadFileFromURL(url: string) {
    isLoading.value = true;

    try {
        const response = await fetch(url);
        const programFile = await response.arrayBuffer();

        pickedFile.value = programFile;
    } finally {
        isLoading.value = false;
    }
}

function loadSampleFile() {
    location.search = "?firmware=https://share.pipe01.net/-XpJvumKzSS/pinetime-app-1.14.0.bin";
}

function loadFile(file: File) {
    const reader = new FileReader();

    reader.onload = () => {
        pickedFile.value = reader.result as ArrayBuffer;
    };

    reader.readAsArrayBuffer(file);
}
</script>

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
            a.btn.btn-primary(:href="sampleUrl")
                | Load sample file

        .form-check.form-switch
            input.form-check-input(type="checkbox" v-model="autoStart" id="autoStart")
            label.form-check-label(for="autoStart") Start emulation after loading file

        .form-check.form-switch
            input.form-check-input(type="checkbox" v-model="initTime" id="initTime")
            label.form-check-label(for="initTime") Set time to current time on watch boot

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
        Emulator(:programFile="pickedFile" :autoStart="autoStart" :initResources="initResources" :initTime="initTime ? new Date() : undefined")
</template>

<script lang="ts" setup>
import { computed, ref } from 'vue';

import Emulator from "@/components/Emulator.vue";
import { resolveArtifactUrl } from './utils';

const pickedFile = ref<ArrayBuffer | null>(null);
const isLoading = ref(0);

const autoStart = ref(true);
const initTime = ref(true);
const initResources = ref<Uint8Array[]>([]);

const sampleUrl = computed(() => {
    const url = new URL(location.href);
    url.searchParams.set("firmware", "https://share.pipe01.net/-XpJvumKzSS/pinetime-app-1.14.0.bin");
    url.searchParams.set("resources", "https://share.pipe01.net/-LJ2sU2m3Yc/infinitime-resources-1.14.0.zip");
    url.searchParams.set("initTime", initTime.value.toString());
    url.searchParams.set("autoStart", autoStart.value.toString());
    return url.toString();
});

async function parseOptions(params: URLSearchParams) {
    isLoading.value++;

    if (params.has("firmware")) {
        await loadFileFromURL(resolveArtifactUrl(params.get("firmware")!));
    }
    if (params.has("resources")) {
        for (const url of params.getAll("resources")) {
            const response = await fetch(resolveArtifactUrl(url));
            const resource = new Uint8Array(await response.arrayBuffer());

            initResources.value.push(resource);
        }
    }
    if (params.has("autoStart")) {
        autoStart.value = params.get("autoStart") == "true";
    }
    if (params.has("initTime")) {
        initTime.value = params.get("initTime") == "true";
    }

    isLoading.value--;
}
parseOptions(new URLSearchParams(location.search));

async function loadFileFromURL(url: string) {
    isLoading.value++;

    try {
        const response = await fetch(url);
        const programFile = await response.arrayBuffer();

        pickedFile.value = programFile;
    } finally {
        isLoading.value--;
    }
}

function loadFile(file: File) {
    const reader = new FileReader();

    reader.onload = () => {
        pickedFile.value = reader.result as ArrayBuffer;
    };

    reader.readAsArrayBuffer(file);
}
</script>

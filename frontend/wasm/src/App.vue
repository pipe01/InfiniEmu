<template lang="pug">
.container.mt-3
    h1 InfiniEmu

    template(v-if="isLoading")
        h1 Loading...
    template(v-else-if="!pickedFile")
        h4 Select a program file
        .mb-3
            input.form-control(type="file" @change="loadFile($event.target.files[0])")

        h4 or 
            button.btn.btn-primary(@click="loadSampleFile") Load sample file
    template(v-else)
        Emulator(:programFile="pickedFile")

    hr

    p
        | InfiniEmu is an emulator that emulates a full PineTime smartwatch, which includes:
        ul
            li NRF52832 along with its ARM Cortex M4 CPU and peripherals, 
            li BMA425 I2C accelerometer
            li CST816S I2C touch screen controller
            li HRS3300 I2C heart rate sensor
            li ST7789 SPI LCD display controller
            li A generic SPI flash based on the XT25F32B-S

    p This website hosts a WebAssembly version of the emulator, which is compiled from the original C code.

    a(href="https://github.com/pipe01/InfiniEmu") View on GitHub
</template>

<script lang="ts" setup>
import { ref } from 'vue';

import Emulator from "@/components/Emulator.vue";

const pickedFile = ref<ArrayBuffer | null>(null);
const isLoading = ref(false);

async function loadSampleFile() {
    isLoading.value = true;

    try {
        const response = await fetch("https://share.pipe01.net/-XpJvumKzSS/pinetime-app-1.14.0.bin");
        const programFile = await response.arrayBuffer();

        pickedFile.value = programFile;
    } finally {
        isLoading.value = false;
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

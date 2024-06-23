<template lang="pug">
.container.mt-3
    template(v-if="isLoading")
        h1 Loading...
    template(v-else-if="!pickedFile")
        h2 Select a program file
        .mb-3
            input.form-control(type="file" @change="loadFile($event.target.files[0])")
        button.btn.btn-primary(@click="loadSampleFile") Load sample file
    template(v-else)
        Emulator(:programFile="pickedFile")
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

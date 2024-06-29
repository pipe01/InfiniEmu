<template lang="pug">
.d-flex.flex-column
    .outer.mb-1(ref="scrollEl")
        .console
            .line(v-for="line in lines" :class="['line-' + line.type]") {{ line.text }}

    div
        input(type="checkbox" v-model="scrollToBottom" id="scrollToBottom")
        label.ms-1(for="scrollToBottom") Scroll to bottom

    form.input-group(@submit.prevent="onSubmit")
        input.form-control(v-model="command" placeholder="Run command (e.g. 'help')")
        button.btn.btn-outline-primary Run
</template>

<script lang="ts">
export type Line = {
    text: string;
    type: "serial" | "command";
}
</script>

<script lang="ts" setup>
import { nextTick, ref, watch } from 'vue';

const props = defineProps<{
    lines: Line[];
}>();

const emit = defineEmits<{
    (e: "runCommand", command: string): void;
}>();

const scrollEl = ref<HTMLDivElement | null>(null);

const command = ref("");
const scrollToBottom = ref(true);

watch(props.lines, () => {
    if (scrollToBottom.value)
        nextTick(() => scrollEl.value?.scroll(0, scrollEl.value?.scrollHeight ?? 0));
});

function onSubmit() {
    if (command.value) {
        emit("runCommand", command.value);
        command.value = "";
    }
}
</script>

<style lang="scss" scoped>
.outer {
    width: 100%;
    overflow-y: auto;
    background-color: black;
}

.console {
    height: 100%;
    width: 100%;
    color: white;
    font-family: 'Courier New', Courier, monospace;
}

.line {
    &:hover {
        background-color: rgba(255, 255, 255, 0.1);
    }

    &.line-serial {
        color: #00FF00;
    }

    &.line-command {
        color: #FF00FF;
    }
}
</style>

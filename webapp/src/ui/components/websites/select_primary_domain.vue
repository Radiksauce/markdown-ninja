<template>
  <sl-select class="w-full"
    :value="selected" @sl-change="selected = $event.target.value">
    <sl-option v-for="domain in domains" :value="domain">{{ domain }}</sl-option>
  </sl-select>
</template>

<script lang="ts" setup>
import { computed, type PropType } from 'vue';
import SlSelect from '@shoelace-style/shoelace/dist/components/select/select.js';
import SlOption from '@shoelace-style/shoelace/dist/components/option/option.js';

// props
const props = defineProps({
  domains: {
    type: Array as PropType<string[]>,
    required: true,
  },
  modelValue: {
    type: String as PropType<string | undefined>,
    required: false,
  },
});


// events
const $emit = defineEmits(['update:modelValue']);

// composables

// lifecycle

// variables

// computed
const selected = computed({
  get(): string | undefined {
    return props.modelValue;
  },
  set(value: string | undefined) {
    $emit('update:modelValue', value);
  }
});

// watch

// functions
</script>

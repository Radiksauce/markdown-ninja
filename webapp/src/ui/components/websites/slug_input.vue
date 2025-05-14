<template>
  <sl-input label="Subdomain (slug)"
    :value="slug" @input="slug = slugify($event.target.value.trim())" @keyup="onKeyup"
  >
    <span name="house" slot="suffix" class="bg-gray-50 h-full content-center px-2 border-l border-gray-300">
      .{{ rootDomain }}
    </span>
  </sl-input>
</template>

<script lang="ts" setup>
import { slugify } from '@/libs/slugify';
import { type PropType, computed } from 'vue';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import { useStore } from '@/app/store';

// props
const props = defineProps({
  modelValue: {
    type: String as PropType<string>,
    required: true,
  },
});

// events
const $emit = defineEmits(['update:modelValue', 'keyup'])

// composables
const $store = useStore();

// lifecycle

// variables
const rootDomain = $store.websitesBaseUrl.replace(/^http(s)?:\/\//g, '');

// computed
const slug = computed({
  get(): string {
    return props.modelValue;
  },
  set(value: string) {
    $emit('update:modelValue', value);
  }
});

// watch

// functions
function onKeyup(event: KeyboardEvent) {
  $emit('keyup', event);
}
</script>

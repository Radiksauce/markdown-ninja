<template>
  <div class="w-full">
    <!-- bg-gray-800 -->
    <div class="coding inverse-toggle px-4 pb-4 shadow-lg text-neutral-100 text-sm font-mono subpixel-antialiased bg-black rounded-lg leading-normal overflow-hidden">
        <div :class="['top flex pt-4 justify-between', showCopyToClipboard || showWindowButtons ? 'pb-3' : '']">
          <div v-if="showWindowButtons" class="flex">
            <div class="h-3 w-3 bg-red-500 rounded-full"></div>
            <div class="ml-2 h-3 w-3 bg-orange-300 rounded-full"></div>
            <div class="ml-2 h-3 w-3 bg-green-500 rounded-full"></div>
          </div>
          <div class="flex" v-if="showCopyToClipboard">
            <button type="button" @click="onCopyToClipboardClicked()" class="cursor-pointer">
              <ClipboardIcon class="-ml-0.5 h-5 w-5 text-gray-400" aria-hidden="true" />
            </button>
          </div>
        </div>

        <div class="flex">
            <span class="text-green-400 content-center">{{ prompt }}</span>
            <pre class="flex-1 typing items-center pl-2 overflow-scroll text-sm bg-transparent mt-0">{{ command }}</pre>
        </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { PropType } from 'vue';
import { ClipboardIcon } from '@heroicons/vue/24/outline';

// props
defineProps({
  prompt: {
    type: String as PropType<string>,
    required: false,
    default: '',
  },
  command: {
    type: String as PropType<string>,
    required: false,
    default: '',
  },
  showWindowButtons: {
    type: Boolean as PropType<boolean>,
    required: false,
    default: true,
  },
  showCopyToClipboard: {
    type: Boolean as PropType<boolean>,
    required: false,
    default: true,
  },
});

// events
const $emit = defineEmits(['copyToClipboardClicked']);

// composables

// lifecycle

// variables

// computed

// watch

// functions
function onCopyToClipboardClicked() {
  $emit('copyToClipboardClicked');
}
</script>

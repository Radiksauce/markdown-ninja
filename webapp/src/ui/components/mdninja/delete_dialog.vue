<template>
  <sl-dialog class="dialog-overview" :open="model" @sl-request-close="onDialogCloseRequest($event)">
    <div slot="label" class="flex flex-row items-center text-xl">
      <div class="mx-auto shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
        <ExclamationTriangleIcon class="h-6 w-6 text-red-600" aria-hidden="true" />
      </div>
      <h2 class="ml-4 font-medium">{{ title }}</h2>
    </div>
    <div class="flex flex-col">
      <div class="mt-2">
        <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
          <div class="flex">
            <div class="ml-3">
              <p class="text-sm text-red-700">
                {{ error }}
              </p>
            </div>
          </div>
        </div>
      </div>
      <div class="flex">
        <p v-if="message" class="text-gray-500">
          {{ message }}
        </p>
      </div>
      <div class="flex mt-3">
        <slot></slot>
      </div>
    </div>
    <div  slot="footer" class="flex mt-5 sm:mt-4 space-x-3 justify-end">
      <sl-button outline @click="close()" :disabled="loading">
        Cancel
      </sl-button>
      <sl-button variant="danger" @click="onDeleteClicked()" :loading="loading">
        Delete
      </sl-button>
    </div>
  </sl-dialog>
</template>

<script lang="ts" setup>
import { type PropType } from 'vue'
import { ExclamationTriangleIcon } from '@heroicons/vue/24/outline'
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';

// props
const model = defineModel({
  type: Boolean as PropType<boolean>,
  required: true,
});

defineProps({
  error: {
    type: String as PropType<string>,
    required: true,
  },
  title: {
    type: String as PropType<string>,
    required: true,
  },
  message: {
    type: String as PropType<string>,
    required: true,
  },
  loading: {
    type: Boolean as PropType<boolean>,
    required: true,
  }
});

// events
const $emit = defineEmits(['delete']);

// composables

// lifecycle

// variables

// computed

// functions
function onDeleteClicked() {
  $emit('delete');
}

function close() {
  model.value = false;
}

function onDialogCloseRequest(event: any) {
  if (event.detail.source !== 'close-button') {
    event.preventDefault();
    return;
  }
  model.value = false;
}
</script>

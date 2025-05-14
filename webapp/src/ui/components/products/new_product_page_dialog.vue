<template>
  <sl-dialog @sl-request-close="show = false" :open="show" label="New Page">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex-1">
      <sl-input :value="title" @input="title = $event.target.value"
        label="Title" placeholder="How to sell online courses" :disabled="loading"
      />
    </div>
<!--
    <div class="flex w-full mt-5">
      <RadioGroup v-model="selectedLessonType" class="w-full">
        <RadioGroupLabel class="sr-only">Server size</RadioGroupLabel>
        <div class="space-y-4">
          <RadioGroupOption as="template" v-for="lessonType in lessonTypes" :key="lessonType.name" :value="lessonType" v-slot="{ active, checked }">
            <div :class="[active ? 'border-(--primary-color) ring-2 ring-(--primary-color)' : 'border-gray-300', 'relative block cursor-pointer rounded-lg border bg-white px-6 py-4 shadow-xs focus:outline-none sm:flex sm:justify-between']">
              <span class="flex items-center">
                <span class="flex flex-col text-sm">
                  <RadioGroupLabel as="span" class="font-medium text-gray-900">{{ lessonType.name }}</RadioGroupLabel>
                  <RadioGroupDescription as="span" class="text-gray-500">
                    <span class="block sm:inline">{{ lessonType.description }}</span>
                  </RadioGroupDescription>
                </span>
              </span>
              <span :class="[active ? 'border' : 'border-2', checked ? 'border-(--primary-color)' : 'border-transparent', 'pointer-events-none absolute -inset-px rounded-lg']" aria-hidden="true" />
            </div>
          </RadioGroupOption>
        </div>
      </RadioGroup>
    </div> -->


    <div slot="footer" class="mt-5 flex space-x-3 place-content-end">
      <sl-button outline @click="close()">
        Cancel
      </sl-button>
      <sl-button variant="primary" :loading="loading" @click="createProductPage()">
        Create
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType } from 'vue';
import { type CreateProductPageInput } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';

// props
const show = defineModel({
  type: Boolean as PropType<boolean>,
  required: true,
});

const props = defineProps({
  productId: {
    type: String as PropType<string>,
    required: true,
  },
});

// events
const $emit = defineEmits(['created']);

// composables
const $mdninja = useMdninja();

// lifecycle

// variables

let error = ref('');
let loading = ref(false);
let title = ref('');
// let selectedLessonType = ref(lessonTypes[0]);

// computed

// watch

// functions
function close() {
  show.value = false;
  resetValues();
}

function resetValues() {
  title.value = '';
}

async function createProductPage() {
  loading.value = true;
  error.value = '';
  const input: CreateProductPageInput = {
    product_id: props.productId,
    title: title.value,
    body_markdown: '',
  };

  try {
    const newPage = await $mdninja.createProductPage(input);
    $emit('created', newPage);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>

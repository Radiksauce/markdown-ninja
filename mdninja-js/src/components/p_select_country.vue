<template>
  <div class="w-full">
    <label for="country" class="block text-sm font-medium leading-6 text-gray-900">Country</label>
    <select v-model="selected" id="country" name="country" :disabled="readonly"
      class="mt-1 cursor-pointer block w-full rounded-md border-0 pt-1.5 pb-2 pl-3 pr-10 text-gray-900 ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-indigo-600 sm:text-sm sm:leading-6">
      <option v-for="country in countries" :value="country.code">
        {{ country.name }}
      </option>
    </select>
  </div>
</template>

<script lang="ts" setup>
import { computed, type PropType } from 'vue';
import countries from '../data/countries';

// props
const props = defineProps({
  modelValue: {
    type: String as PropType<string>,
    required: false,
  },
  readonly: {
    type: Boolean as PropType<boolean>,
    required: false,
    default: false,
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

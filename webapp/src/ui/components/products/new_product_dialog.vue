<template>
  <sl-dialog @sl-request-close="show = false" :open="show" label="New Product">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex">
      <sl-input label="Name" :value="name" @input="name = $event.target.value" type="text"
        :disabled="loading" placeholder="My Product" />
    </div>

    <div class="flex w-full mt-5">
      <sl-input label="Price" :value="price" @input="price = parseInt($event.target.value, 10)" type="number"
        :disabled="loading" pattern="[0-9]*" />
    </div>

    <div class="flex flex-col w-full mt-5">
      <label for="type" class="block text-sm font-medium leading-6 text-gray-900">
        Product Type
      </label>
      <RadioGroup v-model="selectedProductType" class="w-full mt-3">
        <RadioGroupLabel class="sr-only">Server size</RadioGroupLabel>
        <div class="space-y-3">
          <RadioGroupOption as="template" v-for="productType in productTypes" :key="productType.name" :value="productType" v-slot="{ active, checked }">
            <div :class="[active ? 'border-(--primary-color) ring-2 ring-(--primary-color)' : 'border-gray-300', 'relative block cursor-pointer rounded-lg border bg-white px-6 py-4 shadow-xs focus:outline-none sm:flex sm:justify-between']">
              <span class="flex items-center">
                <span class="flex flex-col text-sm">
                  <RadioGroupLabel as="span" class="font-medium text-gray-900">{{ productType.name }}</RadioGroupLabel>
                  <RadioGroupDescription as="span" class="text-gray-500">
                    <span class="block sm:inline">{{ productType.description }}</span>
                  </RadioGroupDescription>
                </span>
              </span>
              <span :class="[active ? 'border' : 'border-2', checked ? 'border-(--primary-color)' : 'border-transparent', 'pointer-events-none absolute -inset-px rounded-lg']" aria-hidden="true" />
            </div>
          </RadioGroupOption>
        </div>
      </RadioGroup>
    </div>


    <div slot="footer" class="mt-5 flex flex-row space-x-3 place-content-end">
      <sl-button outline @click="close()">
        Cancel
      </sl-button>
      <sl-button variant="primary" :loading="loading" @click="createProduct()">
        Create
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType } from 'vue';
import { RadioGroup, RadioGroupDescription, RadioGroupLabel, RadioGroupOption } from '@headlessui/vue';
import { ProductType, type CreateProductInput } from '@/api/model';
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
  websiteId: {
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
const productTypes = [
  { name: 'EBook', description: 'Share your knowledge with others. PDF, EPUB and Kindle.', value: ProductType.Book },
  { name: 'Course', description: 'Create a series of lessons with videos, files, and text.', value: ProductType.Course },
  { name: 'Digital download', description: 'Offer one or more files for download. (e.g. Assets...)', value: ProductType.Download },
];
let selectedProductType = ref(productTypes[0]);

let name = ref('');
let price = ref(29);

// computed

// watch

// functions
function close() {
  show.value = false;
  resetValues();
}

function resetValues() {
  name.value = '';
  selectedProductType = ref(productTypes[0]);
  price.value = 29;
}

async function createProduct() {
  error.value = '';
  let priceNumber = 0;
  try {
    priceNumber = price.value;
    if (isNaN(priceNumber)) {
      throw new Error();
    }
  } catch {
    error.value = 'Price is not valid';
  }

  loading.value = true;
  const input: CreateProductInput = {
    website_id: props.websiteId,
    name: name.value,
    description: '',
    type: selectedProductType.value.value,
    price: priceNumber,
  };

  try {
    const newProduct = await $mdninja.createProduct(input);
    $emit('created', newProduct);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

</script>

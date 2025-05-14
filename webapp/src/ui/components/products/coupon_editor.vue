<template>
  <div class="w-full flex flex-col">

    <div class="rounded-md bg-red-50 p-4 my-5" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex flex-row">
      <div class="flex">
        <RouterLink :to="cancelRoute">
          <sl-button outline>
            Cancel
          </sl-button>
        </RouterLink>
      </div>
      <div class="flex ml-5">
        <sl-button variant="primary" :loading="loading" v-if="coupon" @click="updateCoupon">
          Save
        </sl-button>
        <sl-button variant="primary" @click="createCoupon()" :loading="loading" v-else>
          Create
        </sl-button>
      </div>
    </div>

    <sl-input label="Code" class="mt-5"
      :value="code" @input="code = formatCode($event.target.value)" placeholder="SUMMER-2042"
    />

    <sl-switch v-if="coupon" class="mt-5"
      :checked="archived" @sl-change="archived = $event.target.checked">
      Archived
    </sl-switch>

    <div class="flex flex-col mt-5">
      <div class="flex flex-col w-full">
        <sl-input label="Discount (%)"
          :value="discount" @input="discount = parseInt($event.target.value, 10)" min="0" type="number"
        />
      </div>
    </div>

    <div class="flex flex-col mt-5 w-full">
      <sl-textarea label="Description" :value="description" @input="description = $event.target.value"
        rows="5" :disabled="loading"
      />
    </div>

    <div class="flex flex-col mt-5">
      <h3 class="text-xl">Products</h3>

      <div class="flex mt-5">
        <fieldset>
          <legend class="sr-only">Products</legend>
          <div class="space-y-5">
            <div class="relative flex items-start" v-for="product in products" :key="product.id">
              <div class="flex h-6 items-center">
                <input type="checkbox" :id="product.id" :value="product.id" v-model="selectedProducts"
                  class="cursor-pointer h-4 w-4 rounded border-gray-300 text-(--primary-color)" />
              </div>
              <div class="ml-3 text-sm leading-6">
                <label :for="product.id" class="cursor-pointer font-medium text-gray-900">{{ product.name }}</label>
                {{ ' ' }}
                <span class="text-gray-500">{{ capitalize(product.type) }}</span>
              </div>
            </div>
          </div>
        </fieldset>
      </div>
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { Coupon, CreateCouponInput, Product, UpdateCouponInput } from '@/api/model';
import { ref, type PropType, onBeforeMount, type Ref } from 'vue';
import capitalize from '@/filters/capitalize';
import { useMdninja } from '@/api/mdninja';
import SlSwitch from '@shoelace-style/shoelace/dist/components/switch/switch.js';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { oneRouteUp } from '@/libs/router_utils';
import { useRoute } from 'vue-router';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';

// props
const props = defineProps({
  coupon: {
    type: Object as PropType<Coupon | null>,
    required: false,
    default: null,
  },
  websiteId: {
    type: String as PropType<string>,
    required: true,
  },
  products: {
    type: Array as PropType<Product[]>,
    required: true,
  },
});

// events
const $emit = defineEmits(['created', 'updated']);

// events

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle
onBeforeMount(() => resetValues());

// variables
const cancelRoute = oneRouteUp($route.path);

let loading = ref(false);
let error = ref('');

let code = ref('');
let discount = ref(10);
let description = ref('');
let archived = ref(false);
let selectedProducts: Ref<string[]> = ref([]);

// computed

// watch

// functions
function resetValues() {
  if (props.coupon) {
    code.value = props.coupon.code;
    discount.value = props.coupon.discount;
    description.value = props.coupon.description;
    archived.value = props.coupon.archived;
    selectedProducts.value = props.coupon.products;
  } else {
    code.value = '';
    discount.value = 10;
    description.value = '';
    archived.value = false;
    selectedProducts.value = [];
  }
}

async function createCoupon() {
  loading.value = true;
  error.value = '';

  const input: CreateCouponInput = {
    website_id: props.websiteId,
    code: code.value,
    description: description.value,
    discount: discount.value,
    products: selectedProducts.value,
  };

  try {
    const newCoupon = await $mdninja.createCoupon(input);
    $emit('created', newCoupon);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function formatCode(code: string): string {
  code = code.toUpperCase();
  code = code.replaceAll(' ', '-');
  code = code.replaceAll('.', '-');
  code = code.replaceAll('_', '-');
  code = code.replaceAll('--', '-');
  code = code.trim();
  return code;
}

async function updateCoupon() {
  loading.value = true;
  error.value = '';

  const input: UpdateCouponInput = {
    id: props.coupon!.id,
    code: code.value,
    description: description.value,
    discount: discount.value,
    archived: archived.value,
    products: selectedProducts.value,
  };

  try {
    const updatedCoupon = await $mdninja.updateCoupon(input);
    $emit('updated', updatedCoupon);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>

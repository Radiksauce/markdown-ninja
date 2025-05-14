<template>
  <div>
    <div class="rounded-md bg-red-50 p-2 mb-3 mt-10" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { useStore } from '@/app/store';
import type { CancelOrderInput } from '@/app/model';
import { onBeforeMount, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { cancelOrder } from '@/app/mdninja';

// props

// events

// composables
const $route = useRoute();
const $router = useRouter();
const $store = useStore();

// lifecycle
onBeforeMount(() => {
  callCancelOrder();
});

// variables
let error = ref('');

// computed

// watch

// functions
async function callCancelOrder() {
  error.value = '';
  const cancelOrderInput: CancelOrderInput = {
    order_id: $route.params.order_id as string,
  };

  try {
    await cancelOrder(cancelOrderInput);
    $router.push('/');
  } catch (err: any) {
    error.value = err.message;
  } finally {
    $store.setLoading(false);
  }
}

</script>

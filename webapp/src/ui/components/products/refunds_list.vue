<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                ID
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Date
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Amount
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <tr v-for="refund in refunds" :key="refund.id" @click="showRefund(refund)">
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-2/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ refund.id }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ date(refund.created_at) }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ refund.status }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ refund.amount }} {{ refund.currency }}
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <RefundDialog v-model="showRefundDialog" :refund="refundToShow" />
</template>

<script lang="ts" setup>
import { type Refund } from '@/api/model'
import { ref, type PropType, type Ref } from 'vue'
import date from 'mdninja-js/src/libs/date';
import RefundDialog from '@/ui/components/products/refund_dialog.vue';

// props
defineProps({
  refunds: {
    type: Array as PropType<Refund[]>,
    required: true,
  },
});

// events

// composables

// lifecycle

// variables
let showRefundDialog = ref(false);
let refundToShow: Ref<Refund | null> = ref(null);

// computed

// watch

// functions
function showRefund(refund: Refund) {
  showRefundDialog.value = true;
  refundToShow.value = refund;
}
</script>

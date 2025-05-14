<template>
  <sl-dialog @sl-request-close="show = false" :open="show" label="Refund">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex flex-col w-full mt-5">
      <sl-input label="Amount"
        :value="amount" @input="amount = parseInt($event.target.value, 10)" min="0" type="number"
      />
    </div>

    <div class="flex flex-col mt-6 w-full">
      <div class="flex">
        <h3>
          Reason
        </h3>
      </div>
      <SelectRefuncReason v-model="reason" class="flex" />
    </div>

    <div class="flex mt-6">
      <sl-textarea label="Notes" :value="notes" @input="notes = $event.target.value"
        rows="8" :disabled="loading" placeholder="Detailed reason for the refund and additional information"
      />
    </div>


    <div slot="footer" class="mt-5 flex space-x-3 place-content-end">
      <sl-button outline @click="close()">
        Close
      </sl-button>
      <sl-button variant="primary" v-if="!refund" :loading="loading">
        Create
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType, watch } from 'vue';
import { type Refund, RefundReason } from '@/api/model';
import SelectRefuncReason from '@/ui/components/products/select_refund_reason.vue';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';

// props
const show = defineModel({
  type: Boolean as PropType<boolean>,
  required: true,
});

const props = defineProps({
  orderId: {
    type: String as PropType<string>,
    required: false,
    default: '',
  },
  refund: {
    type: Object as PropType<Refund | null>,
    required: false,
    default: null,
  },
});

// events
const $emit = defineEmits(['created']);

// composables

// lifecycle

// variables
let amount = ref(0);
let reason = ref(RefundReason.RequestedByCustomer);
let notes = ref('');
let error = ref('');
let loading = ref(false);

// computed

// watch
watch(() => props.refund, () => resetValues());

// functions
function close() {
  show.value = false;
  resetValues();
}

function resetValues() {
  if (props.refund) {
    amount.value = props.refund.amount;
    reason.value = props.refund.reason;
    notes.value = props.refund.notes;
  } else {
    amount.value = 0;
    reason.value = RefundReason.RequestedByCustomer;
    notes.value = '';
  }
}

// async function createRefund() {
//   loading.value = true;
//   error.value = '';
//   const input: CreateRefundInput = {
//     order_id: props.orderId,
//     reason: reason.value,
//     notes: notes.value,
//     amount: amount.value,
//   };

//   try {
//     const newRefund = await $mdninja.createRefund(input);
//     $emit('created', newRefund);
//     resetValues();
//   } catch (err: any) {
//     error.value = err.message;
//   } finally {
//     loading.value = false;
//   }
// }
</script>

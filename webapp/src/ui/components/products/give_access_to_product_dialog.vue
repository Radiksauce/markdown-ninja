<template>
  <sl-dialog :open="model" @sl-request-close="model = false" label="Give Access To Product">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex-col mt-2">
      <sl-textarea label="Emails" :value="emails" @input="emails = $event.target.value"
        rows="10" :disabled="loading" :placeholder="emailsPlaceholder"
      />
    </div>


    <div slot="footer" class="mt-5 flex flex-row space-x-3 place-content-end">
      <sl-button outline @click="close()">
        Cancel
      </sl-button>
      <sl-button variant="primary" :loading="loading" @click="giveAccessToProduct()">
        Give Access
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { ref, type PropType } from 'vue';
import { type GiveContactsAccessToProductInput } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';

// props
const model = defineModel({
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

// composables
const $mdninja = useMdninja();

// lifecycle

// variables
const emailsPlaceholder = `email1@email.com
email2@email.com
email3@email.com
...
`

let error = ref('');
let loading = ref(false);
let emails = ref('');

// computed

// watch

// functions
function close() {
  model.value = false;
  resetValues();
}

function resetValues() {
  emails.value = '';
}

async function giveAccessToProduct() {
  loading.value = true;
  error.value = '';
  let emailsApiInput = emails.value.split('\n').map((email) => email.trim()).filter((email) => email !== '');
  const input: GiveContactsAccessToProductInput = {
    emails: emailsApiInput,
    product_id: props.productId,
  };

  try {
    await $mdninja.giveContactAccessToProducts(input);
    close();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>


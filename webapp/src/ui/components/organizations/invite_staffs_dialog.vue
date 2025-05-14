<template>
  <sl-dialog :open="model" @sl-request-close="model = false" label="Invite Staffs">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="mt-1">
      <sl-textarea label="Emails" :value="emailsInput" @input="emailsInput = $event.target.value"
        rows="5" :disabled="loading"
        :placeholder="`someone@example.com\nsomeone.else@example.com`" />
    </div>

    <div slot="footer" class="mt-5 flex flex-row space-x-3 place-content-end">
      <sl-button outline @click="cancel()">
        Cancel
      </sl-button>
      <sl-button variant="primary" :loading="loading" @click="inviteStaffs()">
        Invite
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType } from 'vue';
import { type InviteStaffsInput } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';

// props
const model = defineModel({
  type: Boolean as PropType<boolean>,
  required: true,
});

const props = defineProps({
  organizationId: {
    type: String as PropType<string>,
    required: true,
  },
});

// events
const $emit = defineEmits(['update:modelValue', 'invited']);

// composables
const $mdninja = useMdninja();

// lifecycle

// variables
let error = ref('');
let loading = ref(false);

let emailsInput = ref('');

// computed

// watch

// functions
function cancel() {
  model.value = false;
}

function resetValues() {
  emailsInput.value = '';
}

async function inviteStaffs() {
  error.value = '';
  loading.value = true;

  const emails = emailsInput.value.trim().split('\n');
  const input: InviteStaffsInput = {
    organization_id: props.organizationId,
    emails,
  };

  try {
    const invitations = await $mdninja.inviteStaffs(input);
    $emit('invited', invitations);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>

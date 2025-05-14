<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">Emails</h1>
      <p>Configure how your audience will receive your messages.</p>
    </div>

    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div v-if="configuration" class="flex flex-col space-y-5">
      <sl-input :value="fromName" @input="fromName = $event.target.value.trim()"
        :disabled="loading" label="FROM Name"
        help-text="The name of the sender."
      />

      <sl-input :value="fromAddress" @input="fromAddress = cleanFromAddress($event.target.value)" type="email"
        :disabled="loading" label="FROM Email Address"
        help-text="The address your emails are sent from."
      />

      <div class="flex">
        <sl-button variant="primary" @click="saveConfiguration()" :loading="loading">
          Save
        </sl-button>
      </div>

      <div v-if="configuration.dns_records.length !== 0" class="mt-5 flex flex-col">
        <div class="px-4 sm:px-0">
          <h3 class="text-xl font-medium leading-7 text-gray-900">DNS Configuration</h3>
        </div>

        <p v-if="configuration.domain_verified">
          Verified
        </p>

        <div class="flex flex-col" v-else>
          <p>
            Not Verified
          </p>
          <div>
            <sl-button  variant="primary"
              @click="verifyDnsConfiguration()" :loading="loading">
              Verify
            </sl-button>
          </div>
        </div>

        <DnsRecordsList :records="configuration.dns_records" />

      </div>
    </div>

  </div>
</template>

<script lang="ts" setup>
import type { EmailConfiguration, UpdateEmailConfigurationInput } from '@/api/model';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import { useMdninja } from '@/api/mdninja';
import DnsRecordsList from '@/ui/components/websites/dns_records_list.vue';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

// props

// events

// composables
const $route = useRoute();
const $mdninja = useMdninja();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;

let loading = ref(false);
let error = ref('');
let configuration: Ref<EmailConfiguration | null> = ref(null);
let fromName = ref('');
let fromAddress = ref('');

// computed

// watch

// functions
function resetValues() {
  if (configuration.value) {
    fromName.value = configuration.value.from_name;
    fromAddress.value = configuration.value.from_address;
  } else {
    fromName.value = '';
    fromAddress.value = '';
  }
}

function cleanFromAddress(emailAddress: string): string {
  return emailAddress.trim().toLocaleLowerCase();
}

async function fetchData(){
  loading.value = true;
  error.value = '';

  try {
    configuration.value = await $mdninja.fetchConfiguration(websiteId);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function saveConfiguration() {
  loading.value = true;
  error.value = '';

  const input: UpdateEmailConfigurationInput = {
    website_id: websiteId,
    from_name: fromName.value.trim(),
    from_address: fromAddress.value.trim(),
  };

  try {
    configuration.value = await $mdninja.updateConfiguration(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function verifyDnsConfiguration() {
  loading.value = true;
  error.value = '';

  try {
    configuration.value = await $mdninja.verifyDnsConfiguraiton(websiteId);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>

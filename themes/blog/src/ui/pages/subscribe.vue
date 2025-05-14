<template>
  <div class="my-14 sm:mx-auto sm:w-full sm:max-w-xl">
    <div class="py-8 px-4 sm:rounded-lg sm:px-10">

      <div v-if="$store.contact">
        <h2 class="text-xl font-semibold">Thank you for subscribing!</h2>
        <p class="mt-5">
          The next issue will be coming soon. In the mean time feel free to read the
            <b><PLink href="/blog">past issues</PLink></b>.<br /> <br />

          Also, just so you know, you can always click reply to any issue to give feedback or ask questions.
        </p>
      </div>

      <SubscribeForm v-else-if="!contactId"  @created="onSubscribed" />

      <div v-else class="sm:mx-auto sm:w-full">
        <div class="max-w-xl text-sm text-gray-500">
          <p>
            Please enter the code we just sent you by email to complete your subscription. <br/>
            The code is valid for 1 hour. <br/>
          </p>
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

        <div>
          <label for="name" class="block text-sm font-medium text-gray-700">
            Code
          </label>
          <div class="mt-1">
            <input id="code" name="code" type="text" required :placeholder="codePlaceholder"
              v-model="code" @keyup="cleanupCode" autofocus
              class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-xs
              placeholder-gray-400 focus:outline-hidden focus:ring-[var(--mdninja-accent)]
              focus:border-[var(--mdninja-accent)] sm:text-sm" />
          </div>
        </div>

        <div class="mt-4">
          <PButton @click="callCompleteSubscription()" :loading="loading" :disabled="!canCompleteSignup">
            Complete Singup
          </PButton>
        </div>
      </div>

    </div>
  </div>
</template>

<script lang="ts" setup>
import { completeSubscription } from '@/app/mdninja';
import { computed, onBeforeMount, ref } from 'vue';
import SubscribeForm from '@/ui/components/subscribe_form.vue';
import { useStore } from '@/app/store';
import { useRoute } from 'vue-router';
import { AUTH_CODE_LENGTH, type CompleteSubscriptionInput } from '@/app/model';
import PButton from '@/ui/components/p_button.vue';
import PLink from '@/ui/components/p_link.vue';

// props

// events

// composables
const $store = useStore();
const $route = useRoute();

// lifecycle
onBeforeMount(() => {
  $store.setLoading(false);
  document.title = `${website.name} - Subscribe`;
  if (canCompleteSignup.value) {
    callCompleteSubscription();
  }
});


// variables
const website = $store.website!;
const codePlaceholder = 'XXXXXXXX';

let error = ref('');
let loading = ref(false);
let contactId = ref($route.query.contact as string | undefined ?? '');
let code = ref($route.query.code as string | undefined ?? '');


// computed
const canCompleteSignup = computed(() => code.value.length === AUTH_CODE_LENGTH);

// watch

// functions
function onSubscribed(newContactId: string) {
  contactId.value = newContactId;
}

async function callCompleteSubscription() {
  loading.value = true;
  error.value = '';
  const input: CompleteSubscriptionInput = {
    contact_id: contactId.value,
    code: code.value,
  };

  try {
    await completeSubscription(input);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function cleanupCode() {
  let cleanCode = code.value.toLowerCase().trim();
  if (cleanCode.length > AUTH_CODE_LENGTH) {
    cleanCode = cleanCode.substring(0, AUTH_CODE_LENGTH);
  }
  // cleanCode = cleanCode.split('-').join(''); // remove existing dash (-)
  // cleanCode = cleanCode.match(/.{1,4}/g)?.join('-') ?? cleanCode; // add dash in every 4 characters
  code.value = cleanCode;
}
</script>

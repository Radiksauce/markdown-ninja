<template>
  <div class="mt-14 mb-40 sm:mx-auto sm:w-full sm:max-w-xl">
    <div class="py-8 px-4 sm:rounded-lg sm:px-10">

      <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
        <div class="flex">
          <div class="ml-3">
            <p class="text-sm text-red-700">
              {{ error }}
            </p>
          </div>
        </div>
      </div>

      <div v-if="!sessionId" class="flex flex-col space-y-3">
        <div>
          <b>Log into your account</b>
        </div>

        <div>
          <input id="email" name="email" type="email" autocomplete="email" required placeholder="my@email.com"
            v-model="email" @keyup="lowercaseEmail"
            class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-xs
            placeholder-gray-400 focus:outline-hidden focus:ring-[var(--mdninja-accent)] focus:border-[var(--mdninja-accent)] sm:text-sm" />
        </div>

        <div class="flex items-center justify-between">
          <div class="text-sm">
            Don't have an account yet?
            <PLink class="font-medium"  href="/subscribe">
              Sign up here!
            </PLink>
          </div>
        </div>

        <div class="flex">
          <PButton :loading="loading" @click="onLoginClicked()">
            Log in
          </PButton>
        </div>

      </div>

      <div v-else>
        <div class="mt-2 max-w-xl text-gray-500">
          <p>
            Please enter the code we just sent you by email to complete your authentication. <br/>
            The code is valid for 1 hour. <br/>
          </p>
        </div>

        <div>
          <label for="name" class="block text-sm font-medium text-gray-700">
            Code
          </label>
          <div class="mt-1">
            <input id="code" name="code" type="text" required :placeholder="codePlaceholder"
              v-model="code" @keyup="cleanupCode"
              class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-xs
              placeholder-gray-400 focus:outline-hidden
              focus:ring-[var(--mdninja-accent)] focus:border-[var(--mdninja-accent)] sm:text-sm" />
          </div>
        </div>

        <div class="mt-4">
          <PButton @click="onCompleteLoginClicked()" :loading="loading" :disabled="!canCompleteLogin">
            Log in
          </PButton>
        </div>
      </div>



    </div>
  </div>
</template>

<script lang="ts" setup>
import { computed, onBeforeMount, ref } from 'vue';
import PButton from '@/ui/components/p_button.vue';
import { useStore } from '@/app/store';
import { useRoute, useRouter } from 'vue-router';
import { AUTH_CODE_LENGTH, type CompleteLoginInput } from '@/app/model';
import PLink from '@/ui/components/p_link.vue';
import { completeLogin, login } from '@/app/mdninja';

// props

// events

// composables
const $store = useStore();
const $router = useRouter();
const $route = useRoute();

// lifecycle
onBeforeMount(async () => {
  $store.setLoading(false);
  document.title = `${website.name} - Login`;
  if (canCompleteLogin.value) {
    onCompleteLoginClicked();
  }
})

// variables
const website = $store.website!;
const codePlaceholder = 'XXXXXXXX';


let error = ref('');
let email = ref('');
let loading = ref(false);
let sessionId = ref($route.query.session as string | undefined ?? '');
let code = ref($route.query.code as string | undefined ?? '');

// computed
const canCompleteLogin = computed(() => code.value.length === AUTH_CODE_LENGTH);

// watch

// functions
function lowercaseEmail() {
  email.value = email.value.toLowerCase();
}

async function onLoginClicked() {
  loading.value = true;
  error.value = '';

  try {
    const res = await login(email.value);
    sessionId.value = res.session_id;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function onCompleteLoginClicked() {
  loading.value = true;
  error.value = '';
  const input: CompleteLoginInput = {
    session_id: sessionId.value,
    code: code.value,
  };

  try {
    await completeLogin(input);
    $router.push('/account');
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

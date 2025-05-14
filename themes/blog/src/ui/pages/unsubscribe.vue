<template>
  <div class="mt-8 mb-40 sm:mx-auto sm:w-full sm:max-w-xl">
    <div class="py-8 px-4 sm:rounded-lg sm:px-10">

      <div class="rounded-md bg-red-50 p-4" v-if="error">
        <div class="flex">
          <div class="ml-3">
            <p class="text-sm text-red-700">
              {{ error }}
            </p>
          </div>
        </div>
      </div>

      <div class="sm:mx-auto sm:w-full">
        <div class="max-w-xl text-md text-gray-600">
          <p>
            Please confirm your email address to unsubscribe: <br/>
          </p>
        </div>

        <div class="rounded-md bg-green-50 p-4 my-3" v-if="success">
          <div class="flex">
            <div class="ml-3">
              <p class="text-sm text-green-700">
                {{ success }}
              </p>
            </div>
          </div>
        </div>

        <div>
          <label for="name" class="block text-sm font-medium text-gray-700">
            Email
          </label>
          <div class="mt-1">
            <input id="email" name="email" type="email" required placeholder="my@email.com"
              v-model="email" @keyup="cleanupEmail" autofocus
              class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-xs placeholder-gray-400 focus:outline-hidden focus:ring-sky-500 focus:border-sky-500 sm:text-sm" />
          </div>
        </div>

        <div class="mt-4">
          <PButton @click="onUnsubscribeClicked()" :loading="loading">
            Unsubscribe
          </PButton>
        </div>
      </div>

    </div>
  </div></template>

<script lang="ts" setup>
import type { UnsubscribeInput } from '@/app/model';
import { ref } from 'vue';
import { useRoute } from 'vue-router';
import PButton from '@/ui/components/p_button.vue';
import { unsubscribe } from '@/app/mdninja';

// props

// events

// composables
const $route = useRoute();

// lifecycle

// variables
const token = $route.query.token as string | undefined ?? '';

let error = ref('');
let loading = ref(false);
let email = ref('');
let success = ref('');
let successTimeout: number | undefined = undefined;



// computed

// watch

// functions
function cleanupEmail() {
  email.value = email.value.toLowerCase().trim();
}


async function onUnsubscribeClicked() {
  loading.value = true;
  error.value = '';
  console.log(token)
  const input: UnsubscribeInput = {
    token: token,
    email: email.value,
  };

  try {
    await unsubscribe(input);
    clearTimeout(successTimeout);
    success.value = 'You are now unsubscribed!';
    successTimeout = setTimeout(() => {
      success.value = '';
    }, 5000);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>

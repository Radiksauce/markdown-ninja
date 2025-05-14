<template>
  <div class="my-5">

    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div v-if="subscribed" class="rounded-md bg-green-50 p-4 mb-5">
      <p class="text-md text-green-700">
        Almost finished... We need to confirm your email address to prevent spam. To complete the subscription
          process, please click the link in the email we just sent you.
      </p>
      <!-- <p @click="cancel" class="cursor-pointer">Cancel</p> -->


    </div>

    <div v-else>
      <div class="mb-3">
        <!-- <!- - <b>1 email / week to learn how to (ab)use technology for fun & profit: Programming, Hacking & Entrepreneurship.</b>  - ->
        <! -- <b>1 email / week to learn how to build secure and scalable software systems.</b> -->
         <b>Join the newsletter to get the latest updates</b>
      </div>

      <div>
        <input id="email" name="email" type="email" autocomplete="email" required placeholder="my@email.com"
            v-model="email" @keyup="lowercaseEmail"
            class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md
              shadow-xs placeholder-gray-400 focus:outline-hidden focus:ring-[var(--mdninja-accent)]
              focus:border-[var(--mdninja-accent)] sm:text-sm" />
        <PButton :loading="loading" @click="onSubscribeClicked()" class="mt-3">
          Subscribe
        </PButton>
      </div>

      <div class="mt-1.5">
        <small>
          No spam ever, unsubscribe anytime and we will never share your email.
          You can also grab
          <a target="_blank" href="https://kerkour.com/feed.xml">the RSS feed</a>
        </small>
      </div>
    </div>

  </div>
</template>

<script lang="ts" setup>
import { ref } from 'vue';
import PButton from '@/ui/components/p_button.vue';
import type { SubscribeInput } from '@/app/model';
import { subscribe } from '@/app/mdninja';

// props

// events

// composables

// lifecycle

// variables
let subscribed = ref(false);
let loading = ref(false);
let error = ref('');
let email = ref('');

// computed

// watch

// functions
// function cancel() {
//   subscribed.value = false;
//   error.value = '';
//   email.value = '';
// }

async function onSubscribeClicked() {
  loading.value = true;
  error.value = '';
  const input: SubscribeInput = {
    email: email.value,
  };

  try {
    await subscribe(input);
    subscribed.value = true;
    email.value = '';
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function lowercaseEmail() {
  email.value = email.value.toLowerCase();
}
</script>

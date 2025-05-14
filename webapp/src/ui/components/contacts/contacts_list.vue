<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Email
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Newsletter
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <!-- <tr v-for="contact in contacts" :key="contact.id"> -->
            <RouterLink :to="contactUrl(contact)" v-for="contact in contacts" :key="contact.id"
                class="table-row cursor-pointer min-w-full">
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-2/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ contact.email }}
                  <span v-if="contact.blocked_at" class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                    Blocked
                  </span>
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-2/5">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800" v-if="contact.subscribed_to_newsletter_at">
                  Subscribed
                </span>
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-200" v-else>
                  Unsubscribed
                </span>
              </td>
            </RouterLink>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { Contact } from '@/api/model'
import { type PropType } from 'vue'

// props
defineProps({
  contacts: {
    type: Array as PropType<Contact[]>,
    required: true,
  },
});

// events
const $emit = defineEmits(['delete']);

// composables

// lifecycle

// variables

// computed

// watch

// functions
// function onDeleteContactClicked(contact: Contact, event: MouseEvent) {
//   event.stopPropagation();
//   event.preventDefault();
//   $emit('delete', contact);
// }

function contactUrl(contact: Contact): string {
  return `./contacts/${contact.id}`;
}
</script>

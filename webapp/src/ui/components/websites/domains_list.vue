<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Name
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <tr v-for="domain in domains" :key="domain.id">
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-2/5">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ domain.hostname }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap max-w-0 w-1/5">
                <div class="flex items-center">
                  <!-- <span v-if="domain.tls_active"
                    class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 mx-2">
                    TLS Configured
                  </span>
                  <span v-else @click="onGetTlsCertClicked(domain)"
                    class="text-(--primary-color) hover:text-indigo pr-5 cursor-pointer">
                    Get TLS Certificate
                  </span> -->
                  <sl-button variant="neutral" circle @click="onDeleteDomainClicked(domain)">
                    <TrashIcon class="h-5 w-5" aria-hidden="true" />
                  </sl-button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { Domain } from '@/api/model'
import { type PropType } from 'vue'
import { TrashIcon } from '@heroicons/vue/24/outline'
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';

// props
defineProps({
  domains: {
    type: Array as PropType<Domain[]>,
    required: true,
  },
});

// events
const $emit = defineEmits(['delete', 'checkTls']);

// composables

// lifecycle

// variables

// computed

// watch

// functions
function onDeleteDomainClicked(domain: Domain) {
  $emit('delete', domain);
}

// function onGetTlsCertClicked(domain: Domain) {
//   $emit('checkTls', domain);
// }
</script>

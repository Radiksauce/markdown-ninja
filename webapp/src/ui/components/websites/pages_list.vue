<template>
  <div class="overflow-x-auto min-w-full">
    <div class="py-2 align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="table min-w-full divide-y divide-gray-200">
          <thead class="table-header-group bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Title
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Date
              </th>
              <th v-if="type === PageType.Post" scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Newsletter
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <RouterLink :to="`./${type}s/${page.id}`" v-for="page in pages" :key="page.id"
              class="table-row cursor-pointer min-w-full">
              <div class="table-cell px-6 py-4 whitespace-nowrap max-w-0 w-full">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ page.title }}
                </div>
              </div>
              <div class="table-cell mx-3 px-8 py-4 whitespace-nowrap">
                <div class="text-sm text-gray-900">{{ date(page.date) }}</div>
              </div>
              <div v-if="type === PageType.Post" class="table-cell mx-3 px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                <div v-if="page.send_as_newsletter" class="align-items-center flex">
                  <EnvelopeIcon class="h-5 w-5 text-gray-400 inline align-middle" />
                  <span class="ml-2 align-middle">Sent</span>
                </div>
              </div>
              <div class="table-cell px-6 py-4 whitespace-nowrap">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-200" v-if="page.status === PageStatus.Draft">
                  Draft
                </span>
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800" v-else-if="page.status === PageStatus.Published">
                  Published
                </span>
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800" v-else>
                  Scheduled
                </span>
              </div>
            </RouterLink>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { PageStatus, type PageMetadata, PageType } from '@/api/model'
import { type PropType } from 'vue'
import date from 'mdninja-js/src/libs/date';
import { EnvelopeIcon } from '@heroicons/vue/24/outline'

// props
defineProps({
  pages: {
    type: Array as PropType<PageMetadata[]>,
    required: true,
  },
  type: {
    type: String as PropType<string>,
    required: true,
  },
})

// events

// composables

// lifecycle

// variables

// computed

// watch

// functions
</script>

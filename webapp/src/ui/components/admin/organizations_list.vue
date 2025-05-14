<template>
  <div class="overflow-x-auto min-w-full">
    <div class="align-middle inline-block min-w-full">
      <div class="overflow-hidden border border-gray-300 sm:rounded-lg">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr class="max-w-0">
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Name
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Plan
              </th>
            </tr>
          </thead>
          <tbody class="min-w-full bg-white divide-y divide-gray-200">
            <RouterLink :to="organizationUrl(organization)" v-for="organization in organizations" :key="organization.id"
              class="table-row cursor-pointer min-w-full">
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-md font-medium text-gray-900 truncate">
                  {{ organization.name }}
                </div>
              </td>
              <td class="table-cell px-6 py-4 whitespace-nowrap">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-200" v-if="organization.plan === 'free'">
                  Free
                </span>
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800" v-else>
                  Pro
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
import type { Organization } from '@/api/model';
import type { PropType } from 'vue';

// props
defineProps({
  organizations: {
    type: Array as PropType<Organization[]>,
    required: true,
  },
});

// events

// composables

// lifecycle

// variables

// computed

// watch

// functions
function organizationUrl(org: Organization): string {
  return `/admin/organizations/${org.id}`;
}
</script>

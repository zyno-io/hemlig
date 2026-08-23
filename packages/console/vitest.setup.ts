import { config } from "@vue/test-utils";

// Components resolve router links in isolation; a stub keeps unit tests from
// needing a full router instance.
config.global.stubs = { RouterLink: { template: "<a><slot /></a>" } };

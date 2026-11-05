import {getTestInstance as postgresInstance} from './postgres-fixture.js';
import {organizationFixture} from './organization-fixture.js';
export const getTestInstance=organizationFixture(postgresInstance);

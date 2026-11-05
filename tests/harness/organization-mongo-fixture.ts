import {getTestInstance as mongoInstance} from './mongo-fixture.js';
import {organizationFixture} from './organization-fixture.js';
export const getTestInstance=organizationFixture(mongoInstance);

import {getTestInstance as postgresInstance} from './postgres-fixture.js';
import {adminFixture} from './admin-fixture.js';
export const getTestInstance=adminFixture(postgresInstance);

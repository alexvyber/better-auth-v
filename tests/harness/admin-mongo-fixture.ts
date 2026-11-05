import {getTestInstance as mongoInstance} from './mongo-fixture.js';
import {adminFixture} from './admin-fixture.js';
export const getTestInstance=adminFixture(mongoInstance);

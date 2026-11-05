// Local, checksummed test dependencies. Never installs globally or opens an app DB.
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,mkdirSync,readFileSync,writeFileSync,symlinkSync} from 'node:fs';
import {availableParallelism} from 'node:os';
import {resolve,join} from 'node:path';
const dependencies=resolve('build/deps');mkdirSync(dependencies,{recursive:true});
async function archive(name,url,checksum){
 const path=join(dependencies,name);
 if(!existsSync(path)){
  const response=await fetch(url,{signal:AbortSignal.timeout(120000)});
  if(!response.ok)throw new Error(`Download failed (${response.status}): ${name}`);
  writeFileSync(path,new Uint8Array(await response.arrayBuffer()));
 }
 if(createHash('sha256').update(readFileSync(path)).digest('hex')!==checksum)throw new Error('Archive checksum mismatch: '+name);
 return path;
}
const version='2.5.8';const driverName=`mongo-c-driver-${version}`;
const driverArchive=await archive(driverName+'.tar.gz',`https://github.com/mongodb/mongo-c-driver/releases/download/${version}/${driverName}.tar.gz`,'ea63ec9535f1a425b288b2d72ac3a57c7f3b5d606afde73ff532a175a0774f55');
const source=join(dependencies,driverName);if(!existsSync(source))execFileSync('tar',['-xzf',driverArchive,'-C',dependencies],{stdio:'inherit'});
const build=join(source,'cmake-build');const prefix=join(build,'install');
if(!existsSync(join(prefix,'lib/libmongoc2.a'))){
 const options=['-DCMAKE_BUILD_TYPE=RelWithDebInfo',`-DCMAKE_INSTALL_PREFIX=${prefix}`,'-DENABLE_STATIC=ON','-DENABLE_SHARED=OFF','-DENABLE_TESTS=OFF','-DBUILD_TESTING=OFF','-DENABLE_EXAMPLES=OFF','-DENABLE_CLIENT_SIDE_ENCRYPTION=OFF','-DENABLE_SSL=OPENSSL','-DENABLE_SASL=OFF','-DENABLE_ZLIB=OFF','-DENABLE_ZSTD=OFF','-DENABLE_SNAPPY=OFF','-DUSE_BUNDLED_UTF8PROC=ON'];
 const openssl=process.env.OPENSSL_ROOT_DIR??(process.platform==='darwin'?execFileSync('brew',['--prefix','openssl@3'],{encoding:'utf8'}).trim():undefined);
 if(openssl)options.push(`-DOPENSSL_ROOT_DIR=${openssl}`);
 execFileSync('cmake',['-S',source,'-B',build,...options],{stdio:'inherit'});
 execFileSync('cmake',['--build',build,'-j',String(Math.min(availableParallelism(),8))],{stdio:'inherit'});
 execFileSync('cmake',['--install',build],{stdio:'inherit'});
}
const alias=join(dependencies,'mongoc');if(!existsSync(alias))symlinkSync(prefix,alias,'dir');
if(process.argv.includes('--driver-only')){
 console.log('Native MongoDB driver ready at '+alias);
}else if(process.env.BETTER_AUTH_MONGO_BIN){execFileSync(process.env.BETTER_AUTH_MONGO_BIN,['--version'],{stdio:'inherit'})}
else if(process.platform==='darwin'&&process.arch==='arm64'){
 const name='mongodb-macos-arm64-8.0.6.tgz';
 const serverArchive=await archive(name,`https://fastdl.mongodb.org/osx/${name}`,'a34313ca117b846efe34c1112cbb9fcf0d33f34f4f1837626619b5b01c5b514d');
 const server=join(dependencies,'mongodb-macos-aarch64-8.0.6');
 if(!existsSync(server))execFileSync('tar',['-xzf',serverArchive,'-C',dependencies],{stdio:'inherit'});
 execFileSync(join(server,'bin/mongod'),['--version'],{stdio:'inherit'});
}else{throw new Error('Set BETTER_AUTH_MONGO_BIN to a local mongod binary on this platform; the bundled server is macOS arm64')}

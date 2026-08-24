#import "lite_trust_policy.h"

#ifdef TROLLSTORE_LITE

#import "CodeDirectory.h"
#import "CSBlob.h"
#import "FAT.h"
#import "Host.h"
#import "MachO.h"

extern CS_DecodedBlob *csd_superblob_find_best_code_directory(CS_DecodedSuperBlob *decodedSuperblob);

#define TSL_TXM_TRUST_IDENTITY_VERSION 1
#define TSL_TXM_TRUST_IDENTITY_HASH_MAX 48

typedef struct __attribute__((__packed__)) {
	uint8_t version;
	uint8_t hashType;
	uint8_t hashSize;
	uint8_t anchorCount;
	uint32_t codeLimit;
	uint32_t codeSlotCount;
	int32_t anchorSlots[2];
	uint8_t anchorHashes[2][TSL_TXM_TRUST_IDENTITY_HASH_MAX];
} TSLTXMTrustIdentity;

_Static_assert(sizeof(TSLTXMTrustIdentity) == 116, "unexpected TXM trust identity size");

static BOOL TSLiteCodeDirectoryHashShapeIsValid(uint8_t hashType, uint8_t hashSize)
{
	switch(hashType)
	{
		case CS_HASHTYPE_SHA160_160:
		case CS_HASHTYPE_SHA256_160:
			return hashSize == 20;
		case CS_HASHTYPE_SHA256_256:
			return hashSize == 32;
		case CS_HASHTYPE_SHA384_384:
			return hashSize == 48;
		default:
			return NO;
	}
}

static BOOL TSLiteReadCodeDirectorySlot(CS_DecodedBlob *codeDirectory,
										const CS_CodeDirectory *metadata,
										int32_t slot,
										uint8_t hash[TSL_TXM_TRUST_IDENTITY_HASH_MAX])
{
	uint64_t slotOffset = 0;
	if(slot > 0)
	{
		if((uint32_t)slot >= metadata->nCodeSlots) return NO;
		slotOffset = metadata->hashOffset + (uint64_t)(uint32_t)slot * metadata->hashSize;
	}
	else if(slot < 0)
	{
		uint32_t specialSlot = (uint32_t)-slot;
		if(specialSlot == 0 || specialSlot > metadata->nSpecialSlots) return NO;
		slotOffset = metadata->hashOffset - (uint64_t)specialSlot * metadata->hashSize;
	}
	else
	{
		return NO;
	}

	if(slotOffset > metadata->length || metadata->hashSize > metadata->length - slotOffset) return NO;
	return csd_blob_read(codeDirectory, slotOffset, metadata->hashSize, hash) == 0;
}

static NSString *TSLiteEncodeTrustIdentity(const TSLTXMTrustIdentity *identity)
{
	static const char hex[] = "0123456789abcdef";
	char encoded[sizeof(*identity) * 2 + 1];
	const uint8_t *input = (const uint8_t *)identity;
	for(size_t index = 0; index < sizeof(*identity); index++)
	{
		encoded[index * 2] = hex[input[index] >> 4];
		encoded[index * 2 + 1] = hex[input[index] & 0xf];
	}
	encoded[sizeof(*identity) * 2] = '\0';
	return [NSString stringWithUTF8String:encoded];
}

static NSString *TSLiteTrustIdentityForCodeDirectory(CS_DecodedBlob *codeDirectoryBlob)
{
	size_t blobSize = csd_blob_get_size(codeDirectoryBlob);
	if(blobSize < sizeof(CS_CodeDirectory) || blobSize > UINT32_MAX) return nil;

	CS_CodeDirectory rawCodeDirectory = {0};
	if(csd_blob_read(codeDirectoryBlob, 0, sizeof(rawCodeDirectory), &rawCodeDirectory) != 0) return nil;

	CS_CodeDirectory codeDirectory = rawCodeDirectory;
	CODE_DIRECTORY_APPLY_BYTE_ORDER(&codeDirectory, BIG_TO_HOST_APPLIER);
	if(codeDirectory.magic != CSMAGIC_CODEDIRECTORY || codeDirectory.length < sizeof(CS_CodeDirectory)
	   || codeDirectory.length > blobSize
	   || !TSLiteCodeDirectoryHashShapeIsValid(codeDirectory.hashType, codeDirectory.hashSize)
	   || codeDirectory.hashOffset > codeDirectory.length
	   || codeDirectory.nSpecialSlots > codeDirectory.hashOffset / codeDirectory.hashSize
	   || codeDirectory.nCodeSlots == 0
	   || codeDirectory.nCodeSlots > (codeDirectory.length - codeDirectory.hashOffset) / codeDirectory.hashSize)
	{
		return nil;
	}

	TSLTXMTrustIdentity identity = {
		.version = TSL_TXM_TRUST_IDENTITY_VERSION,
		.hashType = codeDirectory.hashType,
		.hashSize = codeDirectory.hashSize,
		.codeLimit = rawCodeDirectory.codeLimit,
		.codeSlotCount = rawCodeDirectory.nCodeSlots,
	};
	if(codeDirectory.nCodeSlots > 1)
	{
		identity.anchorCount = 1;
		identity.anchorSlots[0] = OSSwapHostToBigInt32(1);
		if(!TSLiteReadCodeDirectorySlot(codeDirectoryBlob,
										  &codeDirectory,
										  1,
										  identity.anchorHashes[0])) return nil;

		if(codeDirectory.nCodeSlots > 2)
		{
			int32_t lastSlot = (int32_t)codeDirectory.nCodeSlots - 1;
			identity.anchorCount = 2;
			identity.anchorSlots[1] = OSSwapHostToBigInt32((uint32_t)lastSlot);
			if(!TSLiteReadCodeDirectorySlot(codeDirectoryBlob,
											  &codeDirectory,
											  lastSlot,
											  identity.anchorHashes[1])) return nil;
		}
	}
	else
	{
		for(uint32_t specialSlot = 1; specialSlot <= codeDirectory.nSpecialSlots; specialSlot++)
		{
			uint8_t hash[TSL_TXM_TRUST_IDENTITY_HASH_MAX] = {0};
			if(!TSLiteReadCodeDirectorySlot(codeDirectoryBlob,
											  &codeDirectory,
											  -(int32_t)specialSlot,
											  hash)) continue;
			BOOL nonzero = NO;
			for(uint8_t index = 0; index < codeDirectory.hashSize; index++) nonzero |= hash[index] != 0;
			if(!nonzero) continue;
			identity.anchorCount = 1;
			identity.anchorSlots[0] = OSSwapHostToBigInt32((uint32_t)-(int32_t)specialSlot);
			memcpy(identity.anchorHashes[0], hash, codeDirectory.hashSize);
			break;
		}
	}

	return identity.anchorCount ? TSLiteEncodeTrustIdentity(&identity) : nil;
}

static NSString *TSLiteTrustIdentityForBinaryAtPath(NSString *binaryPath)
{
	FAT *fat = fat_init_from_path(binaryPath.fileSystemRepresentation);
	if(!fat) return nil;
	MachO *macho = fat_find_preferred_slice(fat);
	CS_SuperBlob *superblob = macho ? macho_read_code_signature(macho) : NULL;
	CS_DecodedSuperBlob *decodedSuperblob = superblob ? csd_superblob_decode(superblob) : NULL;
	free(superblob);
	CS_DecodedBlob *codeDirectory = decodedSuperblob ? csd_superblob_find_best_code_directory(decodedSuperblob) : NULL;
	NSString *identity = codeDirectory ? TSLiteTrustIdentityForCodeDirectory(codeDirectory) : nil;
	if(decodedSuperblob) csd_superblob_free(decodedSuperblob);
	fat_free(fat);
	return identity;
}

static NSString *TSLiteCanonicalBundlePath(NSString *path, NSString *canonicalAppPath)
{
	NSString *canonicalPath = path.stringByResolvingSymlinksInPath.stringByStandardizingPath;
	NSString *rootPrefix = [canonicalAppPath stringByAppendingString:@"/"];
	return [canonicalPath hasPrefix:rootPrefix] ? canonicalPath : nil;
}

static NSString *TSLiteExpandDyldPath(NSString *path, NSString *loaderPath, NSString *executablePath)
{
	if([path isEqualToString:@"@loader_path"]) return loaderPath.stringByDeletingLastPathComponent;
	if([path hasPrefix:@"@loader_path/"])
		return [loaderPath.stringByDeletingLastPathComponent stringByAppendingPathComponent:[path substringFromIndex:13]];
	if([path isEqualToString:@"@executable_path"]) return executablePath.stringByDeletingLastPathComponent;
	if([path hasPrefix:@"@executable_path/"])
		return [executablePath.stringByDeletingLastPathComponent stringByAppendingPathComponent:[path substringFromIndex:17]];
	if([path hasPrefix:@"/"]) return path;
	return [loaderPath.stringByDeletingLastPathComponent stringByAppendingPathComponent:path];
}

static NSString *TSLiteResolveDependency(NSString *dependency,
										NSString *loaderPath,
										NSString *executablePath,
										NSArray<NSString *> *runpaths,
										NSString *canonicalAppPath)
{
	NSMutableArray<NSString *> *candidates = [NSMutableArray new];
	if([dependency hasPrefix:@"@rpath/"])
	{
		NSString *suffix = [dependency substringFromIndex:7];
		for(NSString *runpath in runpaths) [candidates addObject:[runpath stringByAppendingPathComponent:suffix]];
	}
	else
	{
		[candidates addObject:TSLiteExpandDyldPath(dependency, loaderPath, executablePath)];
	}

	for(NSString *candidate in candidates)
	{
		NSString *canonicalPath = TSLiteCanonicalBundlePath(candidate, canonicalAppPath);
		if(canonicalPath && [[NSFileManager defaultManager] fileExistsAtPath:canonicalPath]) return canonicalPath;

		NSRange appSuffix = [candidate rangeOfString:@".app/" options:NSBackwardsSearch];
		if(appSuffix.location == NSNotFound) continue;
		NSString *relocated = [canonicalAppPath stringByAppendingPathComponent:[candidate substringFromIndex:NSMaxRange(appSuffix)]];
		canonicalPath = TSLiteCanonicalBundlePath(relocated, canonicalAppPath);
		if(canonicalPath && [[NSFileManager defaultManager] fileExistsAtPath:canonicalPath]) return canonicalPath;
	}
	return nil;
}

static NSSet<NSString *> *TSLiteDependencyClosure(NSString *rootExecutable, NSString *canonicalAppPath)
{
	NSMutableSet<NSString *> *visited = [NSMutableSet new];
	NSMutableArray<NSDictionary *> *pending = [@[@{ @"path": rootExecutable, @"runpaths": @[] }] mutableCopy];
	while(pending.count)
	{
		NSDictionary *item = pending.lastObject;
		[pending removeLastObject];
		NSString *imagePath = item[@"path"];
		if([visited containsObject:imagePath]) continue;
		[visited addObject:imagePath];

		FAT *fat = fat_init_from_path(imagePath.fileSystemRepresentation);
		MachO *macho = fat ? fat_find_preferred_slice(fat) : NULL;
		if(!macho)
		{
			if(fat) fat_free(fat);
			continue;
		}

		NSMutableArray<NSString *> *runpaths = [NSMutableArray new];
		macho_enumerate_rpaths(macho, ^(const char *rawRunpath, bool *stop) {
			NSString *expanded = TSLiteExpandDyldPath([NSString stringWithUTF8String:rawRunpath], imagePath, rootExecutable);
			NSString *canonical = TSLiteCanonicalBundlePath(expanded, canonicalAppPath);
			if(canonical && ![runpaths containsObject:canonical]) [runpaths addObject:canonical];
		});
		for(NSString *inheritedRunpath in item[@"runpaths"])
			if(![runpaths containsObject:inheritedRunpath]) [runpaths addObject:inheritedRunpath];

		macho_enumerate_dependencies(macho, ^(const char *rawDependency, uint32_t cmd, struct dylib *dylib, bool *stop) {
			NSString *dependency = [NSString stringWithUTF8String:rawDependency];
			NSString *resolved = TSLiteResolveDependency(dependency,
												  imagePath,
												  rootExecutable,
												  runpaths,
												  canonicalAppPath);
			if(resolved && ![visited containsObject:resolved])
				[pending addObject:@{ @"path": resolved, @"runpaths": runpaths.copy }];
		});
		fat_free(fat);
	}
	return visited.copy;
}

NSArray<NSString *> *TSLitePreservedTrustIdentitiesForApp(NSString *appPath,
														  NSArray<NSString *> *launchExecutablePaths)
{
	NSString *canonicalAppPath = appPath.stringByResolvingSymlinksInPath.stringByStandardizingPath;
	NSMutableArray<NSString *> *launchExecutables = [NSMutableArray new];
	for(NSString *path in launchExecutablePaths)
	{
		NSString *canonicalPath = TSLiteCanonicalBundlePath(path, canonicalAppPath);
		if(canonicalPath && ![launchExecutables containsObject:canonicalPath]) [launchExecutables addObject:canonicalPath];
	}

	NSSet<NSString *> *launchExecutableSet = [NSSet setWithArray:launchExecutables];
	NSMutableDictionary<NSString *, NSNumber *> *ownerCounts = [NSMutableDictionary new];
	for(NSString *rootExecutable in launchExecutables)
	{
		for(NSString *dependency in TSLiteDependencyClosure(rootExecutable, canonicalAppPath))
		{
			if([launchExecutableSet containsObject:dependency]) continue;
			ownerCounts[dependency] = @([ownerCounts[dependency] unsignedIntegerValue] + 1);
		}
	}

	NSMutableArray<NSString *> *identities = [NSMutableArray new];
	[ownerCounts enumerateKeysAndObjectsUsingBlock:^(NSString *path, NSNumber *ownerCount, BOOL *stop) {
		if(ownerCount.unsignedIntegerValue <= 1) return;
		NSString *identity = TSLiteTrustIdentityForBinaryAtPath(path);
		if(identity && ![identities containsObject:identity])
		{
			[identities addObject:identity];
		}
		else if(!identity)
		{
			NSLog(@"[signApp] failed to identify shared dependency %@", path);
		}
	}];
	return [identities sortedArrayUsingSelector:@selector(compare:)];
}

#endif

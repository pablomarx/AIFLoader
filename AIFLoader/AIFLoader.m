//
//  AIFLoader.m
//  AIFLoader
//
//  Created by Steve White on 6/11/15.
//  Copyright © 2015 Steve White. All rights reserved.
//

#import "AIFLoader.h"

#define AIF_HEADER_SIZE 128

#if defined(DEBUG) && DEBUG == 1
# define DebugLog(...) NSLog(__VA_ARGS__)
#else
# define DebugLog(...) { }
#endif

@implementation AIFLoader {
  NSObject<HPHopperServices> *_services;

  uint32_t _readOnlySize;
  uint32_t _readWriteSize;
  uint32_t _readWriteOffset;
  uint32_t _debugSize;
}

#pragma mark - AIF
- (void) processDebuggingSymbolsFromData:(const void *)bytes
                                intoFile:(NSObject<HPDisassembledFile> *)file
{
  uint8_t asdversion = OSReadBigInt16(bytes, 6) & 0xff;
  if (asdversion != 2) {
    NSLog(@"Unsupported ASD version: %i", asdversion);
    return;
  }

  uint8_t language = OSReadBigInt16(bytes, 2) & 0xff;
  if (language != 1) {
    NSLog(@"Unsupported language: %i", language);
    return;
  }

  uint32_t readOnlySize = OSReadBigInt32(bytes, 16);
  if (readOnlySize != _readOnlySize) {
    NSLog(@"Read only size differs. AIF header: 0x%08x, debug header: 0x%08x", _readOnlySize, readOnlySize);
    return;
  }

  uint32_t readWriteSize = OSReadBigInt32(bytes, 20);
  if (readWriteSize != _readWriteSize) {
    NSLog(@"Read write size differs. AIF header: 0x%08x, debug header: 0x%08x", _readWriteSize, readWriteSize);
    return;
  }

  uint32_t readWriteOffset = OSReadBigInt32(bytes, 12);
  if (readWriteOffset != _readWriteOffset) {
    NSLog(@"Read write offset differs. AIF header: 0x%08x, debug header: 0x%08x", _readWriteOffset, readWriteOffset);
    return;
  }

  uint32_t debugSize = OSReadBigInt32(bytes, 28);
  if (debugSize != _debugSize) {
    NSLog(@"Debug size differs. AIF header: 0x%08x, debug header: 0x%08x", _debugSize, debugSize);
    return;
  }

  bytes += 32; // skip past header

  uint32_t numOfEntries = OSReadBigInt32(bytes, 0);
  bytes+=4; // advance

  const uint8_t *table = bytes + (numOfEntries * 8);

  uint32_t entry = 0;
  while (entry < numOfEntries) {
    int symbol = OSReadBigInt32(bytes, 0);
    int type = ((symbol >> 24) & 0xff);
    int tableIndex = (symbol & 0x00ffffff);
    int address = OSReadBigInt32(bytes, 4);

    uint8_t nameLen = table[tableIndex];
    NSString *name = [[NSString alloc] initWithBytes:table + tableIndex + 1
                                              length:nameLen
                                            encoding:NSASCIIStringEncoding];

    if ((type & 2) == 2) { // symbol names code
      [file setName:name forVirtualAddress:address reason:NCReason_Import];
      [file addPotentialProcedure:address];
    }
    else if ((type & 4) == 4) { // symbol names data
      [file setName:name forVirtualAddress:address reason:NCReason_Import];
    }

    bytes += 8;
    entry++;
  }
}


#pragma mark - HopperPlugin
- (instancetype)initWithHopperServices:(NSObject<HPHopperServices> *)services {
  self = [super init];
  if (self != nil) {
    _services = services;
  }
  return self;
}

- (NSObject<HPHopperUUID> *)pluginUUID {
  return [_services UUIDWithString:@"491112f1-cf50-458d-8f43-ad59691bc8e8"];
}

- (HopperPluginType)pluginType {
  return Plugin_Loader;
}

- (NSString *)pluginName {
  return @"AIF Loader";
}

- (NSString *)pluginDescription {
  return @"Loader for ARM Image Format files";
}

- (NSString *)pluginAuthor {
  return @"Steve White";
}

- (NSString *)pluginCopyright {
  return @"Copyright © 2015 Steve White";
}

- (NSString *)pluginVersion {
  return @"0.1";
}

- (nonnull NSArray<NSString *> *)commandLineIdentifiers {
  return @[@"AIF"];
}

+ (int)sdkVersion {
  return HOPPER_CURRENT_SDK_VERSION;
}

#pragma mark - FileLoader
- (BOOL)canLoadDebugFiles {
  return YES;
}

/// Returns an array of DetectedFileType objects.
- (nullable NSArray<NSObject<HPDetectedFileType> *> *)detectedTypesForData:(nonnull const void *)bytes
                                                                    length:(size_t)length
                                                               ofFileNamed:(nullable NSString *)filename
                                                                    atPath:(nullable NSString *)fileFullPath
{
  if (length < AIF_HEADER_SIZE) return @[];

  if (OSReadBigInt32(bytes, 0) != 0xE1A00000) { // NOP, aka mov r0, r0
    DebugLog(@"Expected NOP at 0x0");
    return @[];
  }
  if (OSReadBigInt32(bytes, 0x40) != 0xE1A00000) { // NOP, aka mov r0, r0
    DebugLog(@"Expected NOP at 0x40");
    return @[];
  }

  uint32_t readOnlySize = OSReadBigInt(bytes, 0x14);
  uint32_t readWriteSize = OSReadBigInt(bytes, 0x18);
  uint32_t debugSize = OSReadBigInt(bytes, 0x1c);

  if (length != readOnlySize + readWriteSize + debugSize + AIF_HEADER_SIZE) {
    DebugLog(@"data length (%i) != readOnlySize (%i) + readWriteSize (%i) + debugSize (%i) + AIF_HEADER_SIZE (%i)", (int)length, readOnlySize, readWriteSize, debugSize, AIF_HEADER_SIZE);

    return @[];
  }

  DebugLog(@"Good AIF header! r/o size: %i, r/w size: %i, debug size: %i", readOnlySize, readWriteSize, debugSize);

  _readOnlySize = readOnlySize;
  _readWriteSize = readWriteSize;
  _readWriteOffset = OSReadBigInt32(bytes, 0x34);
  if (_readWriteOffset == 0) {
    _readWriteOffset = _readOnlySize;
  }
  _debugSize = debugSize;

  NSObject<HPDetectedFileType> *type = [_services detectedType];
  [type setFileDescription:@"ARM Image Format"];
  [type setAddressWidth:AW_32bits];
  [type setCpuFamily:@"armb"];
  [type setCpuSubFamily:@"v6"];
  [type setShortDescriptionString:@"arm_aif"];
  return @[type];
}


/// Extract a file
/// In the case of a "composite loader", extract the NSData object of the selected file.
- (nullable NSData *)extractFromData:(nonnull const void *)bytes 
                              length:(size_t)length
               usingDetectedFileType:(nonnull NSObject<HPDetectedFileType> *)fileType
                    originalFileName:(nullable NSString *)filename
                        originalPath:(nullable NSString *)fileFullPath
                  returnAdjustOffset:(nullable uint64_t *)adjustOffset
                returnAdjustFilename:(NSString * _Nullable __autoreleasing * _Nullable)newFilename
{
  return nil;
}

/// Load a file.
/// The plugin should create HPSegment and HPSection objects.
/// It should also fill information about the CPU by setting the CPU family, the CPU subfamily and optionally the CPU plugin UUID.
/// The CPU plugin UUID should be set ONLY if you want a specific CPU plugin to be used. If you don't set it, it will be later set by Hopper.
/// During long operations, you should call the provided "callback" block to give a feedback to the user on the loading process.
- (FileLoaderLoadingStatus)loadData:(nonnull const void *)bytes 
                             length:(size_t)length
                       originalPath:(nullable NSString *)fileFullPath
              usingDetectedFileType:(nonnull NSObject<HPDetectedFileType> *)fileType
                            options:(FileLoaderOptions)options
                            forFile:(nonnull NSObject<HPDisassembledFile> *)file
                      usingCallback:(nullable FileLoadingCallbackInfo)callback
{
    if ([[self detectedTypesForData:bytes length:length ofFileNamed:nil atPath:fileFullPath] count] == 0) {
    return DIS_BadFormat;
  }

  uint32_t readOnlySize = OSReadBigInt(bytes, 0x14);
  uint32_t readWriteSize = OSReadBigInt(bytes, 0x18);
  uint32_t debugSize = OSReadBigInt(bytes, 0x1c);

  uint32_t fileOffset = AIF_HEADER_SIZE;

  NSObject<HPSection> *(^createSegmentAndSection)(uint32_t, uint32_t, uint32_t, NSString *) = ^NSObject<HPSection> *(uint32_t fileOffset, uint32_t segmentOffset, uint32_t size, NSString *name)
  {
    NSObject<HPSegment> *segment = [file addSegmentAt:segmentOffset size:size];
    NSObject<HPSection> *section = [segment addSectionAt:segmentOffset size:size];

    segment.segmentName = name;
    section.sectionName = [name lowercaseString];

    segment.fileOffset = fileOffset;
    segment.fileLength = size;
    section.fileOffset = segment.fileOffset;
    section.fileLength = segment.fileLength;

    return section;
  };

  if (readOnlySize != 0) {
    NSObject<HPSection> *section = createSegmentAndSection(fileOffset, 0, readOnlySize, @"CODE");

    section.sectionName = @"code";
    section.pureCodeSection = YES;
    section.containsCode = YES;

    NSData *segmentData = [NSData dataWithBytes:bytes + fileOffset length:readOnlySize];
    section.segment.mappedData = segmentData;

    NSString *comment = [NSString stringWithFormat:@"\n\nRead Only Segment\n\n"];
    [file setComment:comment atVirtualAddress:0 reason:CCReason_Automatic];

    fileOffset += readOnlySize;
  }

  if (readWriteSize != 0) {
    uint32_t segmentOffset = OSReadBigInt32(bytes, 0x34);
    if (segmentOffset == 0) {
      segmentOffset = readOnlySize;
    }

    NSObject<HPSection> *section = createSegmentAndSection(fileOffset, segmentOffset, readWriteSize, @"DATA");
    section.pureDataSection = YES;
    section.containsCode = NO;

    NSString *comment = [NSString stringWithFormat:@"\n\nRead Write Segment\n\n"];
    [file setComment:comment atVirtualAddress:segmentOffset reason:CCReason_Automatic];

    fileOffset += readWriteSize;
  }

  if (debugSize != 0) {
    [self processDebuggingSymbolsFromData:bytes + fileOffset
                                 intoFile:file];


    fileOffset += debugSize;
  }

  file.cpuFamily = @"armb";
  file.cpuSubFamily = @"v6";
  [file setAddressSpaceWidthInBits:32];

  [file addEntryPoint:0];
  callback(@"Loaded ARM Image File", 1.00);
  return DIS_OK;
}


- (FileLoaderLoadingStatus)loadDebugData:(nonnull const void *)bytes
                                  length:(size_t)length
                            originalPath:(nullable NSString *)fileFullPath
                                 forFile:(nonnull NSObject<HPDisassembledFile> *)file
                           usingCallback:(nullable FileLoadingCallbackInfo)callback
{
  return DIS_NotSupported;
}


/// If a loader has extracted data from a container file, it'll get a chance to modify properties
/// of the final file at the end of the loading process. For that, Hopper will call this method on
/// the participating extractors in reverse order.
- (void)setupFile:(nonnull NSObject<HPDisassembledFile> *)file
afterExtractionOf:(nonnull NSString *)filename
     originalPath:(nullable NSString *)fileFullPath
             type:(nonnull NSObject<HPDetectedFileType> *)fileType
{
  // intentionally blank
}

/// Hopper changed the base address of the file, and needs help to fix it up.
/// The address of every segment was shifted of "slide" bytes.
- (void)fixupRebasedFile:(nonnull NSObject<HPDisassembledFile> *)file 
               withSlide:(int64_t)slide
        originalFileData:(nonnull const void *)fileBytes
                  length:(size_t)length
            originalPath:(nullable NSString *)fileFullPath
{
  // intentionally blank
}


@end

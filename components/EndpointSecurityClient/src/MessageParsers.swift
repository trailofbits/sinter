/*
Copyright (c) 2019-present, Trail of Bits, Inc.
All rights reserved.

This source code is licensed in accordance with the terms specified in
the LICENSE file found in the root directory of this source tree.
*/

import EndpointSecurity
import Foundation

func parseExecAuthorization(esMessage: es_message_t) -> EndpointSecurityExecAuthorization? {
    if esMessage.event_type != ES_EVENT_TYPE_AUTH_EXEC {
        return nil
    }

    let target = esMessage.event.exec.target.pointee
    let binaryPath = getProcessBinaryPath(process: target)

    let parentProcessId = target.ppid
    let processId = audit_token_to_pid(target.audit_token)

    let userId = audit_token_to_euid(target.audit_token)
    let groupId = target.group_id

    let signingIdentifier = getProcessSigningId(process: target)
    let teamIdentifier = getProcessTeamId(process: target)

    // The target.is_platform_binary flag is tricky, and basically contains the value
    // of the parent process. In case it's something like bash/zsh, it will get
    // a value of 'true' even though the process being executed may not even
    // be signed.
    //
    // This is because the execve() has completed but the code sections have not
    // been updated yet
    //
    // The code signature is going to be verified before it can be authorized, so
    // let's use the signingIdentifier instead for now
    let platformBinary = signingIdentifier.starts(with: "com.apple.")

    let cdHash = getProcessCdHash(process: target)
    let codeDirectoryHash = BinaryHash(type: BinaryHashType.truncatedSha256,
                                       hash: cdHash)

    let parsedMessage = EndpointSecurityExecAuthorization(binaryPath: binaryPath,
                                                          parentProcessId: pid_t(parentProcessId),
                                                          processId: pid_t(processId),
                                                          userId: uid_t(userId),
                                                          groupId: gid_t(groupId),
                                                          codeDirectoryHash: codeDirectoryHash,
                                                          signingIdentifier: signingIdentifier,
                                                          teamIdentifier: teamIdentifier,
                                                          platformBinary: platformBinary)

    return parsedMessage
}

func parseWriteNotification(esMessage: es_message_t) -> EndpointSecurityFileChangeNotification? {
    let filePath = getFilePath(file: esMessage.event.write.target.pointee)

    let parsedMessage = EndpointSecurityFileChangeNotification(type: EndpointSecurityFileChangeNotificationType.write,
                                                               pathList: [filePath])

    return parsedMessage
}

func parseUnlinkNotification(esMessage: es_message_t) -> EndpointSecurityFileChangeNotification? {
    let filePath = getFilePath(file: esMessage.event.unlink.target.pointee)

    let parsedMessage = EndpointSecurityFileChangeNotification(type: EndpointSecurityFileChangeNotificationType.unlink,
                                                               pathList: [filePath])

    return parsedMessage
}

func parseRenameNotification(esMessage: es_message_t) -> EndpointSecurityFileChangeNotification? {
    let renameEvent = esMessage.event.rename

    let sourceFilePath = getFilePath(file: renameEvent.source.pointee)

    var destinationFilePath = String()
    if renameEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        destinationFilePath = getFilePath(file: renameEvent.destination.existing_file.pointee)

    } else {
        let folderPath = getFilePath(file: renameEvent.destination.new_path.dir.pointee)

        // TODO(alessandro): Use filename.size
        destinationFilePath = folderPath + "/" + String(cString: renameEvent.destination.new_path.filename.data)
    }

    let parsedMessage = EndpointSecurityFileChangeNotification(type: EndpointSecurityFileChangeNotificationType.rename,
                                                               pathList: [sourceFilePath, destinationFilePath])

    return parsedMessage
}

func parseMmapNotification(esMessage: es_message_t) -> EndpointSecurityFileChangeNotification? {
    let mmapEvent = esMessage.event.mmap

    if (mmapEvent.flags & MAP_PRIVATE) != 0 {
        return nil
    }

    if (mmapEvent.protection & PROT_WRITE) == 0 {
        return nil
    }

    let filePath = getFilePath(file: esMessage.event.mmap.source.pointee)
    let parsedMessage = EndpointSecurityFileChangeNotification(type: EndpointSecurityFileChangeNotificationType.mmap,
                                                               pathList: [filePath])

    return parsedMessage
}

func parseLinkNotification(esMessage: es_message_t) -> EndpointSecurityFileChangeNotification? {
    let linkEvent = esMessage.event.link

    let sourceFilePath = getFilePath(file: linkEvent.source.pointee)

    let destinationFolderPath = getFilePath(file: linkEvent.target_dir.pointee)
    let destinationFilePath = destinationFolderPath + "/" + String(cString: linkEvent.target_filename.data)

    let parsedMessage = EndpointSecurityFileChangeNotification(type: EndpointSecurityFileChangeNotificationType.link,
                                                               pathList: [sourceFilePath, destinationFilePath])

    return parsedMessage
}

func parseTruncateNotification(esMessage: es_message_t) -> EndpointSecurityFileChangeNotification? {
    let filePath = getFilePath(file: esMessage.event.truncate.target.pointee)

    let parsedMessage = EndpointSecurityFileChangeNotification(type: EndpointSecurityFileChangeNotificationType.truncate,
                                                               pathList: [filePath])

    return parsedMessage
}

func parseCreateNotification(esMessage: es_message_t) -> EndpointSecurityFileChangeNotification? {
    let createEvent = esMessage.event.create

    var filePath = String()
    if createEvent.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        filePath = getFilePath(file: createEvent.destination.existing_file.pointee)

    } else {
        let folderPath = getFilePath(file: createEvent.destination.new_path.dir.pointee)

        // TODO(alessandro): Use filename.size
        filePath = folderPath + "/" + String(cString: createEvent.destination.new_path.filename.data)
    }

    let parsedMessage = EndpointSecurityFileChangeNotification(type: EndpointSecurityFileChangeNotificationType.create,
                                                               pathList: [filePath])

    return parsedMessage
}

func getFilePath(file: es_file_t) -> String {
    // TODO: use path.size
    String(cString: file.path.data)
}

func getProcessBinaryPath(process: es_process_t) -> String {
    // TODO: is there a better way to detect bundles?
    let binaryPath = getFilePath(file: process.executable.pointee)

    var bundleURL = URL(fileURLWithPath: binaryPath)
    for _ in 1 ... 3 {
        bundleURL.deleteLastPathComponent()
    }

    let bundleCodeSignatureURL = bundleURL.appendingPathComponent("Contents/_CodeSignature")

    let validURLOpt = try? bundleCodeSignatureURL.checkResourceIsReachable()
    if validURLOpt != nil {
        return bundleURL.path
    }

    return binaryPath
}

func getProcessCdHash(process: es_process_t) -> String {
    // Convert the tuple of UInt8 bytes to its hexadecimal string form
    let CDhashArray = CDhash(tuple: process.cdhash).array
    var cdhashHexString: String = ""
    for eachByte in CDhashArray {
        cdhashHexString += String(format: "%02X", eachByte)
    }

    return cdhashHexString
}

func getProcessTeamId(process: es_process_t) -> String {
    var teamIdString: String = ""
    if process.team_id.length > 0 {
        teamIdString = String(cString: process.team_id.data)
    }

    return teamIdString
}

func getProcessSigningId(process: es_process_t) -> String {
    var signingIdString: String = ""
    if process.signing_id.length > 0 {
        signingIdString = String(cString: process.signing_id.data)
    }

    return signingIdString
}

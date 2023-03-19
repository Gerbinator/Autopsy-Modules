import jarray
import inspect
from java.util.logging import Level
from org.sleuthkit.datamodel import Score
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from java.util import Arrays

# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class SampleJythonFileIngestModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Triaged Tails Module"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Triages Data Documentation Based on Actively Used Tails OS directories."

    def getModuleVersionNumber(self):
        return "1.0"

    def isFileIngestModuleFactory(self):
        return True


    def createFileIngestModule(self, ingestOptions):
        return SampleJythonFileIngestModule()


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class SampleJythonFileIngestModule(FileIngestModule):

    _logger = Logger.getLogger(SampleJythonFileIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context
        self.filesFound = 0

        pass


    # TODO: Add your analysis code in here.
    def process(self, file):
        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
                (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()

        tails_array = ["amnesia/Persistent", ".mozilla/firefox.bookmarks", ".cache/thumbnails", "amnesia/Tor Browser/"]
        test_str = str(file.getUniquePath())
        for x in tails_array:
            if x in test_str:
                    attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                              SampleJythonFileIngestModuleFactory.moduleName,
                                                              x))

                    art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                                                 Score.SCORE_LIKELY_NOTABLE,
                                                 None, "Test", None, attrs).getAnalysisResult()

                    try:
                        blackboard.postArtifact(art, SampleJythonFileIngestModuleFactory.moduleName, context.getJobId())
                    except Blackboard.BlackboardException as e:
                        self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

                    artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ITEM)
                    for artifact in artifactList:
                        attributeList = artifact.getAttributes()
                        for attrib in attributeList:
                            self.log(Level.INFO, attrib.toString())

                    # To further the example, this code will read the contents of the file and count the number of bytes
                    inputStream = ReadContentInputStream(file)
                    buffer = jarray.zeros(1024, "b")
                    totLen = 0
                    len = inputStream.read(buffer)
                    while (len != -1):
                        totLen = totLen + len
                        len = inputStream.read(buffer)

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, SampleJythonFileIngestModuleFactory.moduleName,
                str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)
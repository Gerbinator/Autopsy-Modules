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
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from java.util import Arrays

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class SampleJythonFileIngestModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Linux User Script"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Obtains Potentially useful data produced from linux user accounts"

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
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
       
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
                (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        media_array = ["/Downloads", "/Documents", "/Pictures", "/Videos", "/Public", "/Persistent", "/Music"]
        test_str = str(file.getUniquePath())
        if test_str[test_str.find("home") + 5:test_str.find("/") - 1]:
          for x in media_array:
              if x in test_str:
                  attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                            SampleJythonFileIngestModuleFactory.moduleName,
                                                           x))
                  art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                                               Score.SCORE_LIKELY_NOTABLE,
                                               None, "Base User Directories", None, attrs).getAnalysisResult()

                  try:
                      blackboard.postArtifact(art, SampleJythonFileIngestModuleFactory.moduleName, context.getJobId())
                  except Blackboard.BlackboardException as e:
                      self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

                  artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ITEM)
                  for artifact in artifactList:
                      attributeList = artifact.getAttributes()
                      for attrib in attributeList:
                          self.log(Level.INFO, attrib.toString())

                  inputStream = ReadContentInputStream(file)
                  buffer = jarray.zeros(1024, "b")
                  totLen = 0
                  length = inputStream.read(buffer)
                  while (length != -1):
                      totLen = totLen + length
                      length = inputStream.read(buffer)

          if file.getNameExtension() == "sqlite":
              attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                        SampleJythonFileIngestModuleFactory.moduleName,
                                                        "sqlite databases"))
              art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                                           Score.SCORE_LIKELY_NOTABLE,
                                           None, "Sqlite Databases for user", None, attrs).getAnalysisResult()

              try:
                  blackboard.postArtifact(art, SampleJythonFileIngestModuleFactory.moduleName, context.getJobId())
              except Blackboard.BlackboardException as e:
                  self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

              artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ITEM)
              for artifact in artifactList:
                  attributeList = artifact.getAttributes()
                  for attrib in attributeList:
                      self.log(Level.INFO, attrib.toString())

              inputStream = ReadContentInputStream(file)
              buffer = jarray.zeros(1024, "b")
              totLen = 0
              length = inputStream.read(buffer)
              while (length != -1):
                  totLen = totLen + length
                  length = inputStream.read(buffer)

          if ".cache" and "firefox" and "entries" in test_str:
              attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                        SampleJythonFileIngestModuleFactory.moduleName,
                                                        "Firefox Cached entries"))
              art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                                           Score.SCORE_LIKELY_NOTABLE,
                                           None, "Web Cache", None, attrs).getAnalysisResult()

              try:
                  blackboard.postArtifact(art, SampleJythonFileIngestModuleFactory.moduleName, context.getJobId())
              except Blackboard.BlackboardException as e:
                  self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

              artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ITEM)
              for artifact in artifactList:
                  attributeList = artifact.getAttributes()
                  for attrib in attributeList:
                      self.log(Level.INFO, attrib.toString())

              inputStream = ReadContentInputStream(file)
              buffer = jarray.zeros(1024, "b")
              totLen = 0
              length = inputStream.read(buffer)
              while (length != -1):
                  totLen = totLen + length
                  length = inputStream.read(buffer)

        if ".cache" and "thumbnails" and "large" in test_str:
            attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
                                                      SampleJythonFileIngestModuleFactory.moduleName,
                                                      "Cached thumbnail entries"))
            art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT,
                                         Score.SCORE_LIKELY_NOTABLE,
                                         None, "Web Cache", None, attrs).getAnalysisResult()

            try:
                blackboard.postArtifact(art, SampleJythonFileIngestModuleFactory.moduleName, context.getJobId())
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ITEM)
            for artifact in artifactList:
                attributeList = artifact.getAttributes()
                for attrib in attributeList:
                    self.log(Level.INFO, attrib.toString())

            inputStream = ReadContentInputStream(file)
            buffer = jarray.zeros(1024, "b")
            totLen = 0
            length = inputStream.read(buffer)
            while (length != -1):
                totLen = totLen + length
                length = inputStream.read(buffer)

        return IngestModule.ProcessResult.OK

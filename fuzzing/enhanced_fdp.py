# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""
Defines the EnhancedFuzzedDataProvider
"""
from atheris import FuzzedDataProvider


class EnhancedFuzzedDataProvider(FuzzedDataProvider):
    """
    Extends the functionality of FuzzedDataProvider
    """

    def _consume_random_count(self) -> int:
        """
        :return: A count of bytes that is strictly in range 0<=n<=remaining_bytes
        """
        return self.ConsumeIntInRange(0, self.remaining_bytes())

    def ConsumeRandomBytes(self) -> bytes:
        """
        Consume a 'random' count of the remaining bytes
        :return: 0<=n<=remaining_bytes bytes
        """
        return self.ConsumeBytes(self._consume_random_count())

    def ConsumeRemainingBytes(self) -> bytes:
        """
        :return: The remaining buffer
        """
        return self.ConsumeBytes(self.remaining_bytes())

    def ConsumeRandomString(self) -> str:
        """
        Consume a 'random' length string, excluding surrogates
        :return: The string
        """
        return self.ConsumeUnicodeNoSurrogates(self._consume_random_count())

    def ConsumeRemainingString(self) -> str:
        """
        :return: The remaining buffer, as a string without surrogates
        """
        return self.ConsumeUnicodeNoSurrogates(self.remaining_bytes())

    def PickValueInEnum(self, enum):
        return self.PickValueInList([e.value for e in enum])
